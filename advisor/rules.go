/*
 * Copyright 2018 Xiaomi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package advisor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/XiaoMi/soar/ast"
	"github.com/XiaoMi/soar/common"

	"github.com/kr/pretty"
	"github.com/percona/go-mysql/query"
	tidb "github.com/pingcap/parser/ast"
	"vitess.io/vitess/go/vt/sqlparser"
)

// Query4Audit 待评审的SQL结构体，由原SQL和其对应的抽象语法树组成
type Query4Audit struct {
	Query  string              // 查询语句
	Stmt   sqlparser.Statement // 通过Vitess解析出的抽象语法树
	TiStmt []tidb.StmtNode     // 通过TiDB解析出的抽象语法树
}

// NewQuery4Audit return a struct for Query4Audit
func NewQuery4Audit(sql string, options ...string) (*Query4Audit, error) {
	var err, vErr error
	var charset string
	var collation string

	if len(options) > 0 {
		charset = options[0]
	}

	if len(options) > 1 {
		collation = options[1]
	}

	q := &Query4Audit{Query: sql}
	// vitess 语法解析不上报，以 tidb parser 为主
	q.Stmt, vErr = sqlparser.Parse(sql)
	if vErr != nil {
		common.Log.Warn("NewQuery4Audit vitess parse Error: %s, Query: %s", vErr.Error(), sql)
	}

	// TODO: charset, collation
	// tdib parser 语法解析
	q.TiStmt, err = ast.TiParse(sql, charset, collation)
	return q, err
}

// Rule 评审规则元数据结构
type Rule struct {
	Item     string                  `json:"Item"`     // 规则代号
	Severity string                  `json:"Severity"` // 危险等级：L[0-8], 数字越大表示级别越高
	Summary  string                  `json:"Summary"`  // 规则摘要
	Content  string                  `json:"Content"`  // 规则解释
	Case     string                  `json:"Case"`     // SQL示例
	Position int                     `json:"Position"` // 建议所处SQL字符位置，默认0表示全局建议
	Func     func(*Query4Audit) Rule `json:"-"`        // 函数名
}

/*

## Item单词缩写含义

* ALI   Alias(AS)
* ALT   Alter
* ARG   Argument
* CLA   Classic
* COL   Column
* DIS   Distinct
* ERR   Error, 特指MySQL执行返回的报错信息, ERR.000为vitess语法错误，ERR.001为执行错误，ERR.002为EXPLAIN错误
* EXP   Explain, 由explain模块给
* FUN   Function
* IDX   Index, 由index模块给
* JOI   Join
* KEY   Key
* KWR   Keyword
* LCK	Lock
* LIT   Literal
* PRO   Profiling, 由profiling模块给
* RES   Result
* SEC   Security
* STA   Standard
* SUB   Subquery
* TBL   TableName
* TRA   Trace, 由trace模块给

*/

// HeuristicRules 启发式规则列表
var HeuristicRules map[string]Rule

func init() {
	HeuristicRules = map[string]Rule{
		"OK": {
			Item:     "OK",
			Severity: "L0",
			Summary:  "OK",
			Content:  `OK`,
			Case:     "OK",
			Func:     (*Query4Audit).RuleOK,
		},
		"ALI.001": {
			Item:     "ALI.001",
			Severity: "L0",
			Summary:  "It is recommended to use the AS keyword to display an alias.",
			Content:  `In a column or table alias (such as "tbl AS alias"), explicitly using the AS keyword is easier to understand than an implicit alias (such as "tbl alias").`,
			Case:     "select name from tbl t1 where id < 1000",
			Func:     (*Query4Audit).RuleImplicitAlias,
		},
		"ALI.002": {
			Item:     "ALI.002",
			Severity: "L8",
			Summary:  "Setting aliases for column wildcard '*' is not recommended",
			Content:  `Example: "SELECT tbl.* col1, col2" The above SQL has an alias for the column wildcard, so SQL may have a logic error. You might want to query col1, but instead of renaming it is the last column of tbl.`,
			Case:     "select tbl.* as c1,c2,c3 from tbl where id < 1000",
			Func:     (*Query4Audit).RuleStarAlias,
		},
		"ALT.001": {
			Item:     "ALT.001",
			Severity: "L4",
			Summary:  "Do not the alias name of the table or column of the same",
			Content:  ``same table or column aliases and their true names, so alias will make the query harder to distinguish. `,
			Case:     "ALTER TABLE tbl_name CONVERT TO CHARACTER SET charset_name;",
			Func:     (*Query4Audit).RuleAlterCharset,
		},
		"ALT.002": {
			Item:     "ALT.002",
			Severity: "L2",
			Summary:  "ALTER table with more than one article of recommendation together as a request",
			Content:  `Every table structure changes have an impact on the online service will even be able to be adjusted by the number of online tools Please try as much as possible to reduce the operation requested by merging ALTER.`,
			Case:     "ALTER TABLE tbl ADD COLUMN col int, ADD INDEX idx_col (`col`);",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给
		},
		"ALT.003": {
			Item:     "ALT.003",
			Severity: "L0",
			Summary:  "Delete classified as high-risk operation, whether before operating Remember to check the business logic as well as dependence",
			Content:  `Such as business logic relies not completely eliminate, the row is deleted may result in data can not be written or are unable to locate the deleted column data lead to abnormal program. In this case the user will be lost even if the data write requested backup data rewind.`,
			Case:     "ALTER TABLE tbl DROP COLUMN col;",
			Func:     (*Query4Audit).RuleAlterDropColumn,
		},
		"ALT.004": {
			Item:     "ALT.004",
			Severity: "L0",
			Summary:  "Primary and foreign keys remove high-risk operations, verify operation before impact with the DBA",
			Content:  `Primary keys and foreign keys to a relational database two important constraints, remove the existing constraints will break the existing business logic, business development, please confirm before the operation and impact of DBA, think twice.`,
			Case:     "ALTER TABLE tbl DROP PRIMARY KEY;",
			Func:     (*Query4Audit).RuleAlterDropKey,
		},
		"ARG.001": {
			Item:     "ARG.001",
			Severity: "L4",
			Summary:  "Not recommended for use in the preceding paragraph wildcards to find",
			Content:  `For example, "% foo", the query parameter has a wildcard in the case of the preceding paragraph can not use an existing index.`,
			Case:     "select c1,c2,c3 from tbl where name like '%foo'",
			Func:     (*Query4Audit).RulePrefixLike,
		},
		"ARG.002": {
			Item:     "ARG.002",
			Severity: "L1",
			Summary:  "No wildcard LIKE query",
			Content:  `It does not contain a wildcard LIKE query logic errors may exist, because it is logically equivalent to the same query.`,
			Case:     "select c1,c2,c3 from tbl where name like 'foo'",
			Func:     (*Query4Audit).RuleEqualLike,
		},
		"ARG.003": {
			Item:     "ARG.003",
			Severity: "L4",
			Summary:  "Compare parameter contains an implicit conversion, you can not use the index",
			Content:  "Implicit type conversion risk index can not hit, the consequences under high concurrency, large amount of data, the life is not in the index caused very serious.",
			Case:     "SELECT * FROM sakila.film WHERE length >= '60';",
			Func:     (*Query4Audit).RuleOK, // 该建议在IndexAdvisor中给，RuleImplicitConversion
		},
		"ARG.004": {
			Item:     "ARG.004",
			Severity: "L4",
			Summary:  "IN (NULL)/NOT IN (NULL) Non-true forever",
			Content:  "Correct approach is col IN ('val1', 'val2', 'val3') OR col IS NULL",
			Case:     "SELECT * FROM tb WHERE col IN (NULL);",
			Func:     (*Query4Audit).RuleIn,
		},
		"ARG.005": {
			Item:     "ARG.005",
			Severity: "L1",
			Summary:  "IN To be used with caution, elements too much can cause a full table scan",
			Content:  `Such as: select id from t where num in (1,2,3) for successive values ​​BETWEEN can not use the IN: select id from t where num between 1 and 3. When too much value IN MySQL may also enter a full table scan led to a sharp decline in performance.`,
			Case:     "select id from t where num in(1,2,3)",
			Func:     (*Query4Audit).RuleIn,
		},
		"ARG.006": {
			Item:     "ARG.006",
			Severity: "L1",
			Summary:  "Fields should be avoided to a NULL value is determined in the WHERE clause",
			Content:  `Use IS NULL or IS NOT NULL likely to cause the engine to give up using the index and full table scan, such as: select id from t where num is null; may set the default value of 0 on the num, ensuring table num column is not a NULL value, then so that the query: select id from t where num = 0;`,
			Case:     "select id from t where num is null",
			Func:     (*Query4Audit).RuleIsNullIsNotNull,
		},
		"ARG.007": {
			Item:     "ARG.007",
			Severity: "L3",
			Summary:  "Avoid using pattern matching",
			Content:  `The biggest drawback is the performance problems using pattern matching operator. LIKE or use a regular expression pattern matching queries Another issue is likely to return unexpected results. The best solution is to use special search engine technology to replace SQL, such as Apache Lucene. Another option is to save the results up thereby reducing duplication of search overhead. If you must use SQL, consider using third-party extensions like FULLTEXT index in MySQL. But more broadly, you do not have to use SQL to solve all the problems.`,
			Case:     "select c_id,c2,c3 from tbl where c2 like 'test%'",
			Func:     (*Query4Audit).RulePatternMatchingUsage,
		},
		"ARG.008": {
			Item:     "ARG.008",
			Severity: "L1",
			Summary:  "Try to use when OR IN predicate query the index column",
			Content:  `IN-list predicates can be used for index search, and the optimizer can sort the IN-list, to match the ordered sequence index, so as to obtain a more efficient retrieval. Note, IN-list must contain only constant, or kept at constant values ​​during the execution of a query block, e.g. external reference.`,
			Case:     "SELECT c1,c2,c3 FROM tbl WHERE c1 = 14 OR c1 = 17",
			Func:     (*Query4Audit).RuleORUsage,
		},
		"ARG.009": {
			Item:     "ARG.009",
			Severity: "L1",
			Summary:  "Beginning or end of a string of quotes contain spaces",
			Content:  `If the presence of the front and rear spaces VARCHAR column logic may cause problems, such as MySQL 5.5 in 'a' and 'a' may be considered in the query is the same value.`,
			Case:     "SELECT 'abc '",
			Func:     (*Query4Audit).RuleSpaceWithQuote,
		},
		"ARG.010": {
			Item:     "ARG.010",
			Severity: "L1",
			Summary:  "Do not use a hint, such as: sql_no_cache, force index, ignore key, straight join, etc.",
			Content:  `SQL is used to force the hint to be executed in an execution plan, but with the change in the amount of data we can not guarantee that the original pre-judgment is correct.`,
			Case:     "SELECT * FROM t1 USE INDEX (i1) ORDER BY a;",
			Func:     (*Query4Audit).RuleHint,
		},
		"ARG.011": {
			Item:     "ARG.011",
			Severity: "L3",
			Summary:  "Do not use the negative to the query, such as: NOT IN / NOT LIKE",
			Content:  `Please try not to use negative to a query, which will result in a full table scan, a greater impact on query performance.`,
			Case:     "select id from t where num not in(1,2,3);",
			Func:     (*Query4Audit).RuleNot,
		},
		"ARG.012": {
			Item:     "ARG.012",
			Severity: "L2",
			Summary:  "Too much data disposable INSERT / REPLACE of",
			Content:  "Single INSERT / REPLACE statement large quantities of data inserted poor performance, and may even lead to synchronization delay from the library. To improve the performance, reduce the quantities of the write data from the database affect the synchronization delay, the proposed method of inserting batches.",
			Case:     "INSERT INTO tb (a) VALUES (1), (2)",
			Func:     (*Query4Audit).RuleInsertValues,
		},
		"ARG.013": {
			Item:     "ARG.013",
			Severity: "L0",
			Summary:  "DDL Statements using the Chinese full-width quotes",
			Content:  "DDL Statements using the Chinese full-width quotes '' or '', which may be clerical errors, make sure that in line with expectations.",
			Case:     "CREATE TABLE tb (a varchar(10) default '“”'",
			Func:     (*Query4Audit).RuleFullWidthQuote,
		},
		"CLA.001": {
			Item:     "CLA.001",
			Severity: "L4",
			Summary:  "Outermost SELECT WHERE condition is not specified",
			Content:  `SELECT statement has no WHERE clause, you may check more than expected lines (full table scan). For SELECT COUNT (*) If the type of request is not required accuracy, it is recommended to use alternative EXPLAIN or SHOW TABLE STATUS.`,
			Case:     "select id from tbl",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.002": {
			Item:     "CLA.002",
			Severity: "L3",
			Summary:  "Not recommended for use ORDER BY RAND ()",
			Content:  `ORDER BY RAND () to retrieve a stochastic concentration is a very inefficient method of rows from the results, since it would result entire sort and discard most of its data.`,
			Case:     "select name from tbl where id < 1000 order by rand(number)",
			Func:     (*Query4Audit).RuleOrderByRand,
		},
		"CLA.003": {
			Item:     "CLA.003",
			Severity: "L2",
			Summary:  "Not recommended for use with the LIMIT OFFSET query",
			Content:  `LIMIT and OFFSET using the result set page complexity is O (n ^ 2), and will increase as the data lead to performance problems. A "bookmark" method of scanning for higher pagination efficiency.`,
			Case:     "select c1,c2 from tbl where name=xx order by number limit 1 offset 20",
			Func:     (*Query4Audit).RuleOffsetLimit,
		},
		"CLA.004": {
			Item:     "CLA.004",
			Severity: "L2",
			Summary:  "Not recommended for constants GROUP BY",
			Content:  `GROUP BY GROUP BY representation. 1 in a first column. If the GROUP BY clause using digital rather than an expression or column name, column order when changing a query, it can cause problems.`,
			Case:     "select col1,col2 from tbl group by 1",
			Func:     (*Query4Audit).RuleGroupByConst,
		},
		"CLA.005": {
			Item:     "CLA.005",
			Severity: "L2",
			Summary:  "No sense constant ORDER BY column",
			Content:  `There may be errors on SQL logic; at best a useless operation, does not change the results.`,
			Case:     "select id from test where id=1 order by id",
			Func:     (*Query4Audit).RuleOrderByConst,
		},
		"CLA.006": {
			Item:     "CLA.006",
			Severity: "L4",
			Summary:  "GROUP BY or ORDER BY on different tables",
			Content:  `This will force the use of temporary tables and filesort, which may have significant performance problems, and can consume large amounts of memory and temporary space on the disk.`,
			Case:     "select tb1.col, tb2.col from tb1, tb2 where id=1 group by tb1.col, tb2.col",
			Func:     (*Query4Audit).RuleDiffGroupByOrderBy,
		},
		"CLA.007": {
			Item:     "CLA.007",
			Severity: "L2",
			Summary:  "ORDER BY statement uses a different direction for a plurality of different conditions can not be used to sort the index",
			Content:  `ORDER BY clause must be sorted by all expressions of unity ASC or DESC directions for use of the index.`,
			Case:     "select c1,c2,c3 from t1 where c1='foo' order by c2 desc, c3 asc",
			Func:     (*Query4Audit).RuleMixOrderBy,
		},
		"CLA.008": {
			Item:     "CLA.008",
			Severity: "L2",
			Summary:  "Show me add conditions for the GROUP BY ORDER BY",
			Content:  `MySQL will default 'GROUP BY col1, col2, ...' requested sort 'ORDER BY col1, col2, ...' in the following order. If the GROUP BY ORDER BY statement does not specify the condition can lead to unnecessary sorting produce, if not the sort proposed to add 'ORDER BY NULL'.`,
			Case:     "select c1,c2,c3 from t1 where c1='foo' group by c2",
			Func:     (*Query4Audit).RuleExplicitOrderBy,
		},
		"CLA.009": {
			Item:     "CLA.009",
			Severity: "L2",
			Summary:  "ORDER BY conditions for expression",
			Content:  `When the condition is ORDER BY expression or function to use a temporary table, if the result is not specified in the WHERE WHERE condition or return set is large performance will be poor.`,
			Case:     "select description from film where title ='ACADEMY DINOSAUR' order by length-language_id;",
			Func:     (*Query4Audit).RuleOrderByExpr,
		},
		"CLA.010": {
			Item:     "CLA.010",
			Severity: "L2",
			Summary:  "GROUP BY conditions for expression",
			Content:  `When GROUP BY condition expression or function is to use a temporary table, if the result is not specified in the WHERE WHERE condition or return set is large performance will be poor.`,
			Case:     "select description from film where title ='ACADEMY DINOSAUR' GROUP BY length-language_id;",
			Func:     (*Query4Audit).RuleGroupByExpr,
		},
		"CLA.011": {
			Item:     "CLA.011",
			Severity: "L1",
			Summary:  "Recommend add comments to the table",
			Content:  `Add a comment for the table can make a clearer sense of the table, which brings great convenience for future maintenance.`,
			Case:     "CREATE TABLE `test1` (`ID` bigint(20) NOT NULL AUTO_INCREMENT,`c1` varchar(128) DEFAULT NULL,PRIMARY KEY (`ID`)) ENGINE=InnoDB DEFAULT CHARSET=utf8",
			Func:     (*Query4Audit).RuleTblCommentCheck,
		},
		"CLA.012": {
			Item:     "CLA.012",
			Severity: "L2",
			Summary:  "The complex bindings type a query into several simple queries",
			Content:  `SQL is a very expressive language, you can query in a single SQL statement or a single to complete a lot of things. But this does not mean that only one line of code to be mandatory, or that one line of code to get each task is a good idea. To get all the results of the query by a common consequence has been a Cartesian product. When there is no condition between two tables in a query limit their relationship, this situation occurs. There is no corresponding restriction table used directly coupling two queries, each line will get a combination of each row in the first table and the second table. Each of these combinations will become a row of the result set, eventually you'll get the number of a lot of rows in the result set. It is important to consider these queries difficult to write, difficult to modify and difficult to debug. Increasing database query request should be expected to do. Managers who want more sophisticated reports and add more fields in the user interface. If your design is very complex, and is a single query, to extend them will be very time consuming. Regardless of your project or, the time spent on these things above, not worth it. The complex spaghetti query into several simple queries. When you split a complex SQL query, the result may be that many similar queries may only differ in data type. Write all these queries can be tedious, so it is best to have a program to automatically generate the code. SQL code generation is a very good application. Although SQL supports solving complex problems with a single line of code, but do not do unrealistic things.`,
			Case:     "This is a very, very long SQL, case slightly.",
			Func:     (*Query4Audit).RuleSpaghettiQueryAlert,
		},
		/*
			https://www.datacamp.com/community/tutorials/sql-tutorial-query
			The HAVING Clause
			The HAVING clause was originally added to SQL because the WHERE keyword could not be used with aggregate functions. HAVING is typically used with the GROUP BY clause to restrict the groups of returned rows to only those that meet certain conditions. However, if you use this clause in your query, the index is not used, which -as you already know- can result in a query that doesn't really perform all that well.

			If you’re looking for an alternative, consider using the WHERE clause. Consider the following queries:

			SELECT state, COUNT(*)
			  FROM Drivers
			 WHERE state IN ('GA', 'TX')
			 GROUP BY state
			 ORDER BY state
			SELECT state, COUNT(*)
			  FROM Drivers
			 GROUP BY state
			HAVING state IN ('GA', 'TX')
			 ORDER BY state
			The first query uses the WHERE clause to restrict the number of rows that need to be summed, whereas the second query sums up all the rows in the table and then uses HAVING to throw away the sums it calculated. In these types of cases, the alternative with the WHERE clause is obviously the better one, as you don’t waste any resources.

			You see that this is not about limiting the result set, rather about limiting the intermediate number of records within a query.

			Note that the difference between these two clauses lies in the fact that the WHERE clause introduces a condition on individual rows, while the HAVING clause introduces a condition on aggregations or results of a selection where a single result, such as MIN, MAX, SUM,… has been produced from multiple rows.
		*/
		"CLA.013": {
			Item:     "CLA.013",
			Severity: "L3",
			Summary:  "HAVING clause is not recommended",
			Content:  `HAVING clause of the query rewrite the query WHERE clause, you can use the index during query processing.`,
			Case:     "SELECT s.c_id,count(s.c_id) FROM s where c = test GROUP BY s.c_id HAVING s.c_id <> '1660' AND s.c_id <> '2' order by s.c_id",
			Func:     (*Query4Audit).RuleHavingClause,
		},
		"CLA.014": {
			Item:     "CLA.014",
			Severity: "L2",
			Summary:  "Recommended alternative TRUNCATE DELETE When you delete a whole table",
			Content:  `Recommended alternative TRUNCATE DELETE When you delete a whole table`,
			Case:     "delete from tbl",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.015": {
			Item:     "CLA.015",
			Severity: "L4",
			Summary:  "UPDATE WHERE condition is not specified",
			Content:  `UPDATE WHERE condition is not specified, usually fatal, please think twice`,
			Case:     "update tbl set col=1",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.016": {
			Item:     "CLA.016",
			Severity: "L2",
			Summary:  "不要 UPDATE 主键",
			Content:  `A primary key is a unique identifier for the data records in the table is not recommended to frequently update the primary key column, which will affect the metadata information thereby affecting the normal statistical queries.`,
			Case:     "update tbl set col=1",
			Func:     (*Query4Audit).RuleOK, // The proposal to RuleUpdatePrimaryKey in the indexAdvisor
		},
		"COL.001": {
			Item:     "COL.001",
			Severity: "L1",
			Summary:  "不建议使用 SELECT * 类型查询",
			Content:  `When the table structure changes, using the * wildcard to select all columns will lead to meaning and behavior changes when the query, the query returns may result in more data.`,
			Case:     "select * from tbl where id=1",
			Func:     (*Query4Audit).RuleSelectStar,
		},
		"COL.002": {
			Item:     "COL.002",
			Severity: "L2",
			Summary:  "INSERT/REPLACE 未指定列名",
			Content:  `When the table structure is changed, if the INSERT or REPLACE request does not explicitly specify the column name, a request will be different than intended; recommended "INSERT INTO tbl (col1, col2) VALUES ..." instead.`,
			Case:     "insert into tbl values(1,'name')",
			Func:     (*Query4Audit).RuleInsertColDef,
		},
		"COL.003": {
			Item:     "COL.003",
			Severity: "L2",
			Summary:  "It proposed to amend the increment ID unsigned type",
			Content:  `It proposed to amend the increment ID unsigned type`,
			Case:     "create table test(`id` int(11) NOT NULL AUTO_INCREMENT)",
			Func:     (*Query4Audit).RuleAutoIncUnsigned,
		},
		"COL.004": {
			Item:     "COL.004",
			Severity: "L1",
			Summary:  "Please add a default value for a column",
			Content:  `Please add default values ​​for the column, if it is ALTER operation, do not forget to write the original default value on the field. Field with no default, when a large table table structure can not be changed online.`,
			Case:     "CREATE TABLE tbl (col int) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleAddDefaultValue,
		},
		"COL.005": {
			Item:     "COL.005",
			Severity: "L1",
			Summary:  "Column does not add comments",
			Content:  `We recommend add comments for each column in the table, to clarify the meaning and role of each column in the table.`,
			Case:     "CREATE TABLE tbl (col int) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleColCommentCheck,
		},
		"COL.006": {
			Item:     "COL.006",
			Severity: "L3",
			Summary:  "Table contains too many columns",
			Content:  `Table contains too many columns`,
			Case:     "CREATE TABLE tbl ( cols ....);",
			Func:     (*Query4Audit).RuleTooManyFields,
		},
		"COL.007": {
			Item:     "COL.007",
			Severity: "L3",
			Summary:  "Table contains too much text / blob column",
			Content:  fmt.Sprintf(`% D Table contains more than one of text / blob column`, common.Config.MaxTextColsCount),
			Case:     "CREATE TABLE tbl ( cols ....);",
			Func:     (*Query4Audit).RuleTooManyFields,
		},
		"COL.008": {
			Item:     "COL.008",
			Severity: "L1",
			Summary:  "May be used instead of VARCHAR CHAR, VARBINARY place BINARY",
			Content:  `First, variable-length field is a small storage space, you can save storage space. Followed by the query, in a relatively small field of search efficiency is clearly higher.`,
			Case:     "create table t1(id int,name char(20),last_time date)",
			Func:     (*Query4Audit).RuleVarcharVSChar,
		},
		"COL.009": {
			Item:     "COL.009",
			Severity: "L2",
			Summary:  "We recommend the use of precise data type",
			Content:  `In fact, any use FLOAT, REAL, or DOUBLE PRECISION data type of design are likely to be anti-pattern. Most applications use the range of floating-point does not need to reach the maximum / minimum interval defined by the IEEE 754 standard. In calculating the total impact of non-precision floating-point number accumulated serious. The use SQL NUMERIC or DECIMAL FLOAT type and the like instead of the type of data stored in fixed decimal precision. These data types to store data accurately specified when you define the accuracy of this column. Do not use floating-point numbers as possible.`,
			Case:     "CREATE TABLE tab2 (p_id  BIGINT UNSIGNED NOT NULL,a_id  BIGINT UNSIGNED NOT NULL,hours float not null,PRIMARY KEY (p_id, a_id))",
			Func:     (*Query4Audit).RuleImpreciseDataType,
		},
		"COL.010": {
			Item:     "COL.010",
			Severity: "L2",
			Summary:  "We do not recommend the use of ENUM data types",
			Content:  `ENUM defines the type of values ​​in a column, use the value in the ENUM string representation, the data is actually stored in the column ordinal number of them in the definition. Thus, this column data is byte-aligned, when you make a sorting query, the result is stored in accordance with the ordinal value of the actual sorting, rather than alphabetically sorted string of values. This may not be what you want. There's nothing to add or remove a syntax supports value from ENUM or check constraint; you can only use a new set of redefining this column. If you plan to discard an option, you may worry for the historical data. As a strategy, change metadata - that is, change the definition of tables and columns - should be infrequent, and pay attention to testing and quality assurance. There is a better solution to the constraints of an optional value: Create a checklist, with each row containing a candidate appear in the column are allowed; then declare a foreign key constraint on the old table references the new table.`,
			Case:     "create table tab1(status ENUM('new','in progress','fixed'))",
			Func:     (*Query4Audit).RuleValuesInDefinition,
		},
		// The proposal to migrate from sqlcheck, the actual production environment each build SQL table will give this advice, I saw a lot will not be happy.
		"COL.011": {
			Item:     "COL.011",
			Severity: "L0",
			Summary:  "The only constraint when needed to use NULL, not only when there are missing values ​​using a column NOT NULL",
			Content:  `NULL and 0 are different, multiplied by 10 NULL or NULL. NULL and empty string is not the same. The standard SQL and a string of NULL unite the result was NULL. NULL and FALSE are different. AND, OR and NOT Boolean operators if it involves three NULL, the result is also a lot of people confused. When you declare a NOT NULL, meaning that for every value in this column must exist and be meaningful. Null value to indicate a NULL does not exist any type. When you declare a NOT NULL, meaning that for every value in this column must exist and be meaningful.`,
			Case:     "select c1,c2,c3 from tbl where c4 is null or c4 <> 1",
			Func:     (*Query4Audit).RuleNullUsage,
		},
		"COL.012": {
			Item:     "COL.012",
			Severity: "L5",
			Summary:  "BLOB and TEXT types of fields is not recommended to NOT NULL",
			Content:  `BLOB and TEXT types of fields can not specify a non-NULL default value, if you add a NOT NULL restriction, write time and not likely to lead to a write failure to specify the value of the field.`,
			Case:     "CREATE TABLE `tb`(`c` longblob NOT NULL);",
			Func:     (*Query4Audit).RuleBLOBNotNull,
		},
		"COL.013": {
			Item:     "COL.013",
			Severity: "L4",
			Summary:  "TIMESTAMP Type Default abnormalities",
			Content:  `TIMESTAMP type is recommended to set the default values, and do not recommend using 0 as a default value or 0000-00-00 00:00:00. Consider using 1970-08-02 01:01:01`,
			Case:     "CREATE TABLE tbl( `id` bigint not null, `create_time` timestamp);",
			Func:     (*Query4Audit).RuleTimestampDefault,
		},
		"COL.014": {
			Item:     "COL.014",
			Severity: "L5",
			Summary:  "Specified for the column character set",
			Content:  `Recommended columns and tables use the same character set, do not specify the character set column alone.`,
			Case:     "CREATE TABLE `tb2` ( `id` int(11) DEFAULT NULL, `col` char(10) CHARACTER SET utf8 DEFAULT NULL)",
			Func:     (*Query4Audit).RuleColumnWithCharset,
		},
		// https://stackoverflow.com/questions/3466872/why-cant-a-text-column-have-a-default-value-in-mysql
		"COL.015": {
			Item:     "COL.015",
			Severity: "L4",
			Summary:  "TEXT and BLOB fields not specify the type of non-NULL defaults",
			Content:  `TEXT MySQL database and BLOB fields not specify the type of non-NULL default value. TEXT maximum length of 2 ^ 16-1 characters, MEDIUMTEXT maximum length of 2 ^ 32-1 characters, LONGTEXT maximum length of 2 ^ 64-1 characters.`,
			Case:     "CREATE TABLE `tbl` (`c` blob DEFAULT NULL);",
			Func:     (*Query4Audit).RuleBlobDefaultValue,
		},
		"COL.016": {
			Item:     "COL.016",
			Severity: "L1",
			Summary:  "Integer defined recommended INT (10) or BIGINT (20)",
			Content:  `INT (M) in the integer data type, M represents the maximum width of the display. In INT (M), M values ​​with INT (M) percentage how much storage space does not have any relationship. INT (3), INT (4), INT (8) on a disk are occupied by 4 bytes of storage space. High version of MySQL has not recommended to set the display width of an integer.`,
			Case:     "CREATE TABLE tab (a INT(1));",
			Func:     (*Query4Audit).RuleIntPrecision,
		},
		"COL.017": {
			Item:     "COL.017",
			Severity: "L2",
			Summary:  "VARCHAR defined too long",
			Content:  fmt.Sprintf(`varchar Variable length strings, not pre-allocated storage space, a length not more than% d, if the memory length is too long, MySQL will define field type text, an independent list, with the corresponding primary key, to avoid affecting the efficiency index of other fields.`, common.Config.MaxVarcharLength),
			Case:     "CREATE TABLE tab (a varchar(3500));",
			Func:     (*Query4Audit).RuleVarcharLength,
		},
		"COL.018": {
			Item:     "COL.018",
			Severity: "L1",
			Summary:  "Construction of the table statement does not recommend the use of field types",
			Content:  "The following field types are not recommended：" + strings.Join(common.Config.ColumnNotAllowType, ","),
			Case:     "CREATE TABLE tab (a BOOLEAN);",
			Func:     (*Query4Audit).RuleColumnNotAllowType,
		},
		"COL.019": {
			Item:     "COL.019",
			Severity: "L1",
			Summary:  "Time data is not recommended in the second stage of use of the following types of precision",
			Content:  "Bring high-precision data type storage time is relatively large space consumption; the MySQL can support accurate to the microsecond time data types 5.6.4 above, need to be considered when using the version compatibility problems.",
			Case:     "CREATE TABLE t1 (t TIME(3), dt DATETIME(6));",
			Func:     (*Query4Audit).RuleTimePrecision,
		},
		"DIS.001": {
			Item:     "DIS.001",
			Severity: "L1",
			Summary:  "Eliminating unnecessary DISTINCT conditions",
			Content:  `Too many DISTINCT condition is a symptom complex bindings type queries. Consider creating complex queries into a number of simple queries and reduce the number DISTINCT conditions. If the primary key column is part of the result set for the column, the DISTINCT may have no effect.`,
			Case:     "SELECT DISTINCT c.c_id,count(DISTINCT c.c_name),count(DISTINCT c.c_e),count(DISTINCT c.c_n),count(DISTINCT c.c_me),c.c_d FROM (select distinct id, name from B) as e WHERE e.country_id = c.country_id",
			Func:     (*Query4Audit).RuleDistinctUsage,
		},
		"DIS.002": {
			Item:     "DIS.002",
			Severity: "L3",
			Summary:  "When the multi-column results COUNT (DISTINCT) may differ from what you want it",
			Content:  `COUNT (DISTINCT col) calculate the number of rows do not overlap other than the NULL column, note COUNT (DISTINCT col, col2) If a NULL is full even if the other row have different values, it returns 0.`,
			Case:     "SELECT COUNT(DISTINCT col, col2) FROM tbl;",
			Func:     (*Query4Audit).RuleCountDistinctMultiCol,
		},
		// DIS.003 Inspired by the link below
		// http://www.ijstr.org/final-print/oct2015/Query-Optimization-Techniques-Tips-For-Writing-Efficient-And-Faster-Sql-Queries.pdf
		"DIS.003": {
			Item:     "DIS.003",
			Severity: "L3",
			Summary:  "DISTINCT * 对有主键的表没有意义",
			Content:  `When the table has a primary key, it outputs the result DISTINCT results for all columns DISTINCT not operate the same, do not superfluous.`,
			Case:     "SELECT DISTINCT * FROM film;",
			Func:     (*Query4Audit).RuleDistinctStar,
		},
		"FUN.001": {
			Item:     "FUN.001",
			Severity: "L2",
			Summary:  "Avoid the use of other operators in the WHERE condition",
			Content:  `Although the use of functions in SQL can simplify many complex queries, but use the query function can not use the index table has been established, the query will be poor full table scan performance. It is always advisable to write the name of the column to the left of comparison operators, comparison operators will query filter condition on the right side. Do not recommend writing on both sides of the extra brackets if the query conditions, which have a relatively large reading problems.`,
			Case:     "select id from t where substring(name,1,3)='abc'",
			Func:     (*Query4Audit).RuleCompareWithFunction,
		},
		"FUN.002": {
			Item:     "FUN.002",
			Severity: "L1",
			Summary:  "COUNT is specified using the WHERE conditions or non-MyISAM engine (*) poor operating performance",
			Content:  `Role COUNT (*) is the number of tables lines, the role COUNT (COL) is a statistical specified number of lines of non-NULL columns. For MyISAM tables COUNT (*) counts the number of rows whole table has been specially optimized Under normal circumstances very quickly. But for the non-MyISAM table or specify a certain WHERE conditions, COUNT (*) operation requires a large number of rows to scan in order to obtain accurate results, and therefore poor performance. Sometimes some service scenarios do not require full accuracy COUNT values, an approximation can be replaced at this time. EXPLAIN out the number of rows the optimizer estimates is a good approximation, the implementation of EXPLAIN does not really need to execute the query, so the cost is very low.`,
			Case:     "SELECT c3, COUNT(*) AS accounts FROM tab where c2 < 10000 GROUP BY c3 ORDER BY num",
			Func:     (*Query4Audit).RuleCountStar,
		},
		"FUN.003": {
			Item:     "FUN.003",
			Severity: "L3",
			Summary:  "The combined use of a column to be an empty string is connected",
			Content:  `In some queries, you need to force a column or an expression returns non-NULL value, so that the query logic easier, but do not want to survive this value. You can use the COALESCE () function to construct an expression connected, so that even a null value does not cause the entire column expression becomes NULL.`,
			Case:     "select c1 || coalesce(' ' || c2 || ' ', ' ') || c3 as c from tbl",
			Func:     (*Query4Audit).RuleStringConcatenation,
		},
		"FUN.004": {
			Item:     "FUN.004",
			Severity: "L4",
			Summary:  "Not recommended SYSDATE () function",
			Content:  `SYSDATE () function may result in inconsistent data from the master, use NOW () function instead SYSDATE ().`,
			Case:     "SELECT SYSDATE();",
			Func:     (*Query4Audit).RuleSysdate,
		},
		"FUN.005": {
			Item:     "FUN.005",
			Severity: "L1",
			Summary:  "Not recommended for use COUNT (col) or COUNT (constant)",
			Content:  `Do not use COUNT (col) or COUNT (constant) to replace the COUNT (*), COUNT (*) is the standard statistical method the number of rows SQL92 definition, has nothing to do with the data, with NULL and non-NULL has nothing to do.`,
			Case:     "SELECT COUNT(1) FROM tbl;",
			Func:     (*Query4Audit).RuleCountConst,
		},
		"FUN.006": {
			Item:     "FUN.006",
			Severity: "L1",
			Summary:  "NPE should pay attention to the problem when using the SUM (COL)",
			Content:  `NPE should pay attention to a problem when the value of the whole column is NULL, COUNT (COL) returns a value of 0, the SUM (COL) returns a value of NULL, and therefore use SUM (). May be used in the following manner to avoid the problem of SUM NPE: SELECT IF (ISNULL (SUM (COL)), 0, SUM (COL)) FROM tbl`,
			Case:     "SELECT SUM(COL) FROM tbl;",
			Func:     (*Query4Audit).RuleSumNPE,
		},
		"FUN.007": {
			Item:     "FUN.007",
			Severity: "L1",
			Summary:  "Not recommended for use triggers",
			Content:  `Execution of a trigger and without feedback logs, hides the actual implementation of the steps, when the database problem is that the specific implementation can not slow log analysis trigger, difficult to find the problem. In MySQL, the trigger can not be temporarily closed or open, migration or data recovery scenario in the data, you need to trigger a temporary drop may affect the production environment.`,
			Case:     "CREATE TRIGGER t1 AFTER INSERT ON work FOR EACH ROW INSERT INTO time VALUES(NOW());",
			Func:     (*Query4Audit).RuleForbiddenTrigger,
		},
		"FUN.008": {
			Item:     "FUN.008",
			Severity: "L1",
			Summary:  "We do not recommend the use of stored procedures",
			Content:  `No versioning stored procedures, stored procedures with the business of upgrading difficult to do business without perception. Stored Procedures are also problems in the development and migration.`,
			Case:     "CREATE PROCEDURE simpleproc (OUT param1 INT);",
			Func:     (*Query4Audit).RuleForbiddenProcedure,
		},
		"FUN.009": {
			Item:     "FUN.009",
			Severity: "L1",
			Summary:  "We do not recommend the use of a custom function",
			Content:  `We do not recommend the use of a custom function`,
			Case:     "CREATE FUNCTION hello (s CHAR(20));",
			Func:     (*Query4Audit).RuleForbiddenFunction,
		},
		"GRP.001": {
			Item:     "GRP.001",
			Severity: "L2",
			Summary:  "Not recommended for the equivalent GROUP BY query column",
			Content:  `GROUP BY columns used in the previous equivalent query WHERE condition, such a column GROUP BY little significance.`,
			Case:     "select film_id, title from film where release_year='2006' group by release_year",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给 RuleGroupByConst
		},
		"JOI.001": {
			Item:     "JOI.001",
			Severity: "L2",
			Summary:  "JOIN statement mix commas and ANSI mode",
			Content:  `Time-table joins and ANSI JOIN mix comma is not easy to understand humans, and the behavior of different versions of MySQL table joins and priorities are different, when the MySQL version change may introduce errors.`,
			Case:     "select c1,c2,c3 from t1,t2 join t3 on t1.c1=t2.c1,t1.c3=t3,c1 where id>1000",
			Func:     (*Query4Audit).RuleCommaAnsiJoin,
		},
		"JOI.002": {
			Item:     "JOI.002",
			Severity: "L4",
			Summary:  "It is connected to the same table twice",
			Content:  `It appears at least twice in the same table in the FROM clause can be simplified to a single access to the table.`,
			Case:     "select tb1.col from (tb1, tb2) join tb2 on tb1.id=tb.id where tb1.id=1",
			Func:     (*Query4Audit).RuleDupJoin,
		},
		"JOI.003": {
			Item:     "JOI.003",
			Severity: "L4",
			Summary:  "OUTER JOIN Fail",
			Content:  `Since such error OUTER JOIN WHERE condition table no external data is returned, it will be converted to an implicit query INNER JOIN. Such as: select c from L left join R using (c) where L.a = 5 and R.b = 10. It may exist on this SQL logic error or misunderstanding of the programmer how to work OUTER JOIN, because LEFT / RIGHT JOIN is LEFT / RIGHT OUTER JOIN acronym.`,
			Case:     "select c1,c2,c3 from t1 left outer join t2 using(c1) where t1.c2=2 and t2.c3=4",
			Func:     (*Query4Audit).RuleOK, // TODO
		},
		"JOI.004": {
			Item:     "JOI.004",
			Severity: "L4",
			Summary:  "We do not recommend the use of exclusive JOIN",
			Content:  `Only the right side of the table is NULL WHERE clause LEFT OUTER JOIN statement, there may be used an error in the WHERE clause are listed, such as: "... FROM l LEFT OUTER JOIN r ON ll = rr WHERE rz IS NULL ", this query may be correct logic WHERE rr iS NULL.`,
			Case:     "select c1,c2,c3 from t1 left outer join t2 on t1.c1=t2.c1 where t2.c2 is null",
			Func:     (*Query4Audit).RuleOK, // TODO
		},
		"JOI.005": {
			Item:     "JOI.005",
			Severity: "L2",
			Summary:  "JOIN reduce the number of",
			Content:  `Too many JOIN is a symptom complex bindings type queries. Consider creating complex queries into a number of simple queries and reduce the number of JOIN.`,
			Case:     "select bp1.p_id, b1.d_d as l, b1.b_id from b1 join bp1 on (b1.b_id = bp1.b_id) left outer join (b1 as b2 join bp2 on (b2.b_id = bp2.b_id)) on (bp1.p_id = bp2.p_id ) join bp21 on (b1.b_id = bp1.b_id) join bp31 on (b1.b_id = bp1.b_id) join bp41 on (b1.b_id = bp1.b_id) where b2.b_id = 0",
			Func:     (*Query4Audit).RuleReduceNumberOfJoin,
		},
		"JOI.006": {
			Item:     "JOI.006",
			Severity: "L4",
			Summary:  "The nested query rewrite JOIN usually leads to more efficient and more effective implementation of optimization",
			Content:  `In general, for a non-nested subquery always correlated subquery, up from a table in the FROM clause, the query predicates for these sub ANY, ALL EXISTS and the. If, at most subqueries The semantics of the query returns a row determinant, then a subquery or unrelated to the FROM clause of a plurality of tables to be pressed flat.`,
			Case:     "SELECT s,p,d FROM tbl WHERE p.p_id = (SELECT s.p_id FROM tbl WHERE s.c_id = 100996 AND s.q = 1 )",
			Func:     (*Query4Audit).RuleNestedSubQueries,
		},
		"JOI.007": {
			Item:     "JOI.007",
			Severity: "L4",
			Summary:  "It does not recommend the use of contingency tables delete or update",
			Content:  `Recommended when you need to delete or update multiple tables at the same time using a simple statement, a SQL only delete or update a table, try not to operate multiple tables in the same statement.`,
			Case:     "UPDATE users u LEFT JOIN hobby h ON u.id = h.uid SET u.name = 'pianoboy' WHERE h.hobby = 'piano';",
			Func:     (*Query4Audit).RuleMultiDeleteUpdate,
		},
		"JOI.008": {
			Item:     "JOI.008",
			Severity: "L4",
			Summary:  "Do not use the JOIN query across databases",
			Content:  `In general, cross-database JOIN query means queries across two different subsystems, which may mean coupling system is too high or database table design unreasonable.`,
			Case:     "SELECT s,p,d FROM tbl WHERE p.p_id = (SELECT s.p_id FROM tbl WHERE s.c_id = 100996 AND s.q = 1 )",
			Func:     (*Query4Audit).RuleMultiDBJoin,
		},
		// TODO: Cross-examination of library affairs, currently SOAR not do transaction processing
		"KEY.001": {
			Item:     "KEY.001",
			Severity: "L2",
			Summary:  "Since additional recommended as a primary key, used in combination as the primary key self-energizing self-energizing key set as the first column",
			Content:  `Since additional recommended as a primary key, used in combination as the primary key self-energizing self-energizing key set as the first column`,
			Case:     "create table test(`id` int(11) NOT NULL PRIMARY KEY (`id`))",
			Func:     (*Query4Audit).RulePKNotInt,
		},
		"KEY.002": {
			Item:     "KEY.002",
			Severity: "L4",
			Summary:  "No primary key or unique key, can not change the table structure online",
			Content:  `No primary key or unique key, can not change the table structure online`,
			Case:     "create table test(col varchar(5000))",
			Func:     (*Query4Audit).RuleNoOSCKey,
		},
		"KEY.003": {
			Item:     "KEY.003",
			Severity: "L4",
			Summary:  "To avoid the recurrence relation of keys, etc.",
			Content:  `Data exists recursive relationship is very common, often like a tree or data hierarchically organized. However, creating a foreign key constraint to enforce the relationship between the two in the same table, it can lead to awkward queries. Each layer of the tree corresponds to the other connector. You will need to issue a recursive query to get all descendants or ancestors of all nodes. Solution is to construct a closure attached table. It records the relationships between all nodes in the tree, not just those with a direct parent-child relationship. You can also compare different levels of design data: Closures table, path enumeration, nested sets. Then select a required application.`,
			Case:     "CREATE TABLE tab2 (p_id  BIGINT UNSIGNED NOT NULL,a_id  BIGINT UNSIGNED NOT NULL,PRIMARY KEY (p_id, a_id),FOREIGN KEY (p_id) REFERENCES tab1(p_id),FOREIGN KEY (a_id) REFERENCES tab3(a_id))",
			Func:     (*Query4Audit).RuleRecursiveDependency,
		},
		// TODO: New composite index, the field scattered by the particle size whether descending order, the highest distinction in the leftmost
		"KEY.004": {
			Item:     "KEY.004",
			Severity: "L0",
			Summary:  "Reminder: Please be aligned with the query sequence index properties",
			Content:  `If the column to create a composite index, make sure the order of queries and index properties property for DBMS using an index when processing queries. If the query and index attributes orders are not aligned, then the DBMS may not be able to use the index during query processing.`,
			Case:     "create index idx1 on tbl (last_name,first_name)",
			Func:     (*Query4Audit).RuleIndexAttributeOrder,
		},
		"KEY.005": {
			Item:     "KEY.005",
			Severity: "L2",
			Summary:  "Table overindexing built",
			Content:  `Table overindexing built`,
			Case:     "CREATE TABLE tbl ( a int, b int, c int, KEY idx_a (`a`),KEY idx_b(`b`),KEY idx_c(`c`));",
			Func:     (*Query4Audit).RuleTooManyKeys,
		},
		"KEY.006": {
			Item:     "KEY.006",
			Severity: "L4",
			Summary:  "Excessive primary key column",
			Content:  `Excessive primary key column`,
			Case:     "CREATE TABLE tbl ( a int, b int, c int, PRIMARY KEY(`a`,`b`,`c`));",
			Func:     (*Query4Audit).RuleTooManyKeyParts,
		},
		"KEY.007": {
			Item:     "KEY.007",
			Severity: "L4",
			Summary:  "Primary or primary key or a non-int Not specified bigint",
			Content:  `No primary or primary key or a non-int bigint, recommended to set the primary key or unsigned int bigint unsigned.`,
			Case:     "CREATE TABLE tbl (a int);",
			Func:     (*Query4Audit).RulePKNotInt,
		},
		"KEY.008": {
			Item:     "KEY.008",
			Severity: "L4",
			Summary:  "ORDER BY multiple columns, but not the sort direction at the same time may not use the index",
			Content:  `Before MySQL 8.0 when ORDER BY multiple columns specified is not the same sort direction will not be able to use the index has been established.`,
			Case:     "SELECT * FROM tbl ORDER BY a DESC, b ASC;",
			Func:     (*Query4Audit).RuleOrderByMultiDirection,
		},
		"KEY.009": {
			Item:     "KEY.009",
			Severity: "L0",
			Summary:  "Before adding a unique index Please note that the only checks data",
			Content:  `Please check ahead of time to add unique data unique index column, if not unique online data table structure adjustment will be possible to automatically delete duplicate columns, which may result in data loss.`,
			Case:     "CREATE UNIQUE INDEX part_of_name ON customer (name(10));",
			Func:     (*Query4Audit).RuleUniqueKeyDup,
		},
		"KEY.010": {
			Item:     "KEY.010",
			Severity: "L0",
			Summary:  "Full-text index is not a silver bullet",
			Content:  `Full-text index is mainly used to solve the problem of fuzzy query performance, but need to control the frequency and degree of concurrency good query. At the same time pay attention to adjust ft_min_word_len, ft_max_word_len, ngram_token_size and other parameters.`,
			Case:     "CREATE TABLE `tb` ( `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `ip` varchar(255) NOT NULL DEFAULT '', PRIMARY KEY (`id`), FULLTEXT KEY `ip` (`ip`) ) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleFulltextIndex,
		},
		"KWR.001": {
			Item:     "KWR.001",
			Severity: "L2",
			Summary:  "SQL_CALC_FOUND_ROWS low efficiency",
			Content:  `Because SQL_CALC_FOUND_ROWS not scale well, it may lead to performance issues; proposed business use other strategies to replace the counting function SQL_CALC_FOUND_ROWS offer, such as: paged results show and so on.`,
			Case:     "select SQL_CALC_FOUND_ROWS col from tbl where id>1000",
			Func:     (*Query4Audit).RuleSQLCalcFoundRows,
		},
		"KWR.002": {
			Item:     "KWR.002",
			Severity: "L2",
			Summary:  "We do not recommend the use of MySQL keywords column name or table name",
			Content:  `When using the keyword as a column or table names in the program you need to table names and column names escape, if negligence was the cause request can not be performed.`,
			Case:     "CREATE TABLE tbl ( `select` int )",
			Func:     (*Query4Audit).RuleUseKeyWord,
		},
		"KWR.003": {
			Item:     "KWR.003",
			Severity: "L1",
			Summary:  "We do not recommend the use of a complex table names or column names",
			Content:  `Table names should only represent an entity table of contents inside, should not represent the number of entities, DO corresponding to the class name is singular, idiomatic.`,
			Case:     "CREATE TABLE tbl ( `books` int )",
			Func:     (*Query4Audit).RulePluralWord,
		},
		"KWR.004": {
			Item:     "KWR.004",
			Severity: "L1",
			Summary:  "Not recommended to use multi-byte character encoding (Chinese) name",
			Content:  `For the library, tables, columns, recommend the use of English, numbers, underscores and other characters, does not recommend the use of Chinese or other multi-byte character encoding alias name.`,
			Case:     "select col as 列 from tb",
			Func:     (*Query4Audit).RuleMultiBytesWord,
		},
		"LCK.001": {
			Item:     "LCK.001",
			Severity: "L3",
			Summary:  "INSERT INTO xx SELECT locking granularity greater caution",
			Content:  `INSERT INTO xx SELECT locking granularity greater caution`,
			Case:     "INSERT INTO tbl SELECT * FROM tbl2;",
			Func:     (*Query4Audit).RuleInsertSelect,
		},
		"LCK.002": {
			Item:     "LCK.002",
			Severity: "L3",
			Summary:  "Use caution INSERT ON DUPLICATE KEY UPDATE",
			Content:  `Use INSERT ON DUPLICATE KEY UPDATE when the primary key is auto-increment primary keys keys may cause a large number of non-continuous rapid growth, the primary key can not continue to write quickly overflow. In extreme cases it may also lead to a master-slave data inconsistencies.`,
			Case:     "INSERT INTO t1(a,b,c) VALUES (1,2,3) ON DUPLICATE KEY UPDATE c=c+1;",
			Func:     (*Query4Audit).RuleInsertOnDup,
		},
		"LIT.001": {
			Item:     "LIT.001",
			Severity: "L2",
			Summary:  "IP address with the character type storage",
			Content:  `It looks like a string literal IP address, but not INET_ATON () parameter indicates the character data is stored as an integer instead. The IP address is stored as an integer more effective.`,
			Case:     "insert into tbl (IP,name) values('10.20.306.122','test')",
			Func:     (*Query4Audit).RuleIPString,
		},
		"LIT.002": {
			Item:     "LIT.002",
			Severity: "L4",
			Summary:  "Date / time is not used quotes",
			Content:  `Queries such as "WHERE col <2010-02-12" and the like are effective SQL, but it would be a mistake, because it will be interpreted as a "WHERE col <1996"; date / time text should be quoted.`,
			Case:     "select col1,col2 from tbl where time < 2018-01-10",
			Func:     (*Query4Audit).RuleDataNotQuote,
		},
		"LIT.003": {
			Item:     "LIT.003",
			Severity: "L3",
			Summary:  "Storing a series of data collection",
			Content:  `The ID is stored as a list, as VARCHAR / TEXT columns, this can cause performance and data integrity problems. Queries such a column requires the use of pattern matching expressions. Use a comma-separated list of multi-table join queries do locate a row of data is extremely elegant and time-consuming. This will make it more difficult to verify ID. Consider, for a list of how much data is stored up to support it? It will be a separate table, instead of using multi-value storage attribute ID, attribute value such that each individual row are occupied. Such cross table to achieve the many relationships between two tables. This will simplify the query better, more efficiently verify ID.`,
			Case:     "select c1,c2,c3,c4 from tab1 where col_id REGEXP '[[:<:]]12[[:>:]]'",
			Func:     (*Query4Audit).RuleMultiValueAttribute,
		},
		"LIT.004": {
			Item:     "LIT.004",
			Severity: "L1",
			Summary:  "Please use a semicolon or the end DELIMITER set",
			Content:  `USE database, SHOW DATABASES commands also need to use a semicolon or the end DELIMITER has been set.`,
			Case:     "USE db",
			Func:     (*Query4Audit).RuleOK, // TODO: RuleAddDelimiter
		},
		"RES.001": {
			Item:     "RES.001",
			Severity: "L4",
			Summary:  "Non-deterministic GROUP BY",
			Content:  `SQL return neither column nor row aggregate function in GROUP BY expression, so the results of these values ​​will be non-deterministic. Such as: select a, b, c from tbl where foo = "bar" group by a, the result is returned by SQL indeterminate.`,
			Case:     "select c1,c2,c3 from t1 where c2='foo' group by c2",
			Func:     (*Query4Audit).RuleNoDeterministicGroupby,
		},
		"RES.002": {
			Item:     "RES.002",
			Severity: "L4",
			Summary:  "Not use the LIMIT ORDER BY queries",
			Content:  `No ORDER BY LIMIT will lead to the non-deterministic results, depending on the query execution plan.`,
			Case:     "select col1,col2 from tbl where name=xx limit 10",
			Func:     (*Query4Audit).RuleNoDeterministicLimit,
		},
		"RES.003": {
			Item:     "RES.003",
			Severity: "L4",
			Summary:  "UPDATE / DELETE operation conditions used LIMIT",
			Content:  `UPDATE / DELETE operations using LIMIT conditions and do not add WHERE conditions as dangerous as it can lead to a master-slave data will be inconsistent or synchronous interrupt from the library.`,
			Case:     "UPDATE film SET length = 120 WHERE title = 'abc' LIMIT 1;",
			Func:     (*Query4Audit).RuleUpdateDeleteWithLimit,
		},
		"RES.004": {
			Item:     "RES.004",
			Severity: "L4",
			Summary:  "UPDATE / DELETE operations specified conditions ORDER BY",
			Content:  `UPDATE / DELETE operations do not specify ORDER BY condition.`,
			Case:     "UPDATE film SET length = 120 WHERE title = 'abc' ORDER BY title",
			Func:     (*Query4Audit).RuleUpdateDeleteWithOrderby,
		},
		"RES.005": {
			Item:     "RES.005",
			Severity: "L4",
			Summary:  "UPDATE statement possible logic error, resulting in data corruption",
			Content:  "In an UPDATE statement, if you want to update multiple fields, between fields you can not use the AND, and should be separated by commas.",
			Case:     "update tbl set col = 1 and cl = 2 where col=3;",
			Func:     (*Query4Audit).RuleUpdateSetAnd,
		},
		"RES.006": {
			Item:     "RES.006",
			Severity: "L4",
			Summary:  "Never really compare conditions",
			Content:  "Query forever is not true, if the condition appears where the inquiry could lead to no matching results.",
			Case:     "select * from tbl where 1 != 1;",
			Func:     (*Query4Audit).RuleImpossibleWhere,
		},
		"RES.007": {
			Item:     "RES.007",
			Severity: "L4",
			Summary:  "Always true comparison condition",
			Content:  "Query is always true, it could lead to failure of a full table WHERE condition queries.",
			Case:     "select * from tbl where 1 = 1;",
			Func:     (*Query4Audit).RuleMeaninglessWhere,
		},
		"RES.008": {
			Item:     "RES.008",
			Severity: "L2",
			Summary:  "Not recommended LOAD DATA / SELECT ... INTO OUTFILE",
			Content:  "SELECT INTO OUTFILE FILE need to grant permission, which will be introduced by security issues. LOAD DATA Although the rate of introduction of data can be improved, but also may result in an excessive delay from the database synchronization.",
			Case:     "LOAD DATA INFILE 'data.txt' INTO TABLE db2.my_table;",
			Func:     (*Query4Audit).RuleLoadFile,
		},
		"RES.009": {
			Item:     "RES.009",
			Severity: "L2",
			Summary:  "We do not recommend the use of continuous judgment",
			Content:  "Like this SELECT * FROM tbl WHERE col = col = 'abc' statement may be clerical error, meaning you might want to express col = 'abc'. If that is the business requirements and recommend changes to col = col and col = 'abc'.",
			Case:     "SELECT * FROM tbl WHERE col = col = 'abc'",
			Func:     (*Query4Audit).RuleMultiCompare,
		},
		"RES.010": {
			Item:     "RES.010",
			Severity: "L2",
			Summary:  "Construction of the table statement is defined as the ON UPDATE CURRENT_TIMESTAMP fields contain the business logic is not recommended",
			Content:  "It is defined as the ON UPDATE CURRENT_TIMESTAMP fields modified when the linkage table updates other fields, if the business logic will be visible to the user lay hidden. If batch follow-up data but do not want to modify the changes will result in an error when the data field.",
			Case: `CREATE TABLE category (category_id TINYINT UNSIGNED NOT NULL AUTO_INCREMENT,	name VARCHAR(25) NOT NULL, last_update TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY  (category_id)`,
			Func: (*Query4Audit).RuleCreateOnUpdate,
		},
		"RES.011": {
			Item:     "RES.011",
			Severity: "L2",
			Summary:  "Comprising a table update request operation field ON UPDATE CURRENT_TIMESTAMP",
			Content:  "It is defined as the ON UPDATE CURRENT_TIMESTAMP fields modified when the linkage table updates other fields, check the note. The update time not want to modify the field can use the following method: UPDATE category SET name = 'ActioN', last_update = last_update WHERE category_id = 1",
			Case:     "UPDATE category SET name='ActioN', last_update=last_update WHERE category_id=1",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给 RuleUpdateOnUpdate
		},
		"SEC.001": {
			Item:     "SEC.001",
			Severity: "L0",
			Summary:  "Please use caution TRUNCATE operation",
			Content:  `Generally want to empty the quickest approach is to use a table TRUNCATE TABLE tbl_name; statement. But TRUNCATE operation is not costless, TRUNCATE TABLE can not return the exact number of rows to be deleted, if you need to return the number of rows to be deleted recommended DELETE syntax. TRUNCATE operation also resets AUTO_INCREMENT, if not want to reset the value recommended DELETE FROM tbl_name WHERE 1; alternative. TRUNCATE operation will add the source data dictionary data latch (the MDL), when a table needs TRUNCATE affects many instances throughout all requests, so long DROP CREATE a manner to reduce lock To + TRUNCATE recommendations multiple tables.`,
			Case:     "TRUNCATE TABLE tbl_name",
			Func:     (*Query4Audit).RuleTruncateTable,
		},
		"SEC.002": {
			Item:     "SEC.002",
			Severity: "L0",
			Summary:  "Do not store passwords in plain text",
			Content:  `Use passwords stored in plain text or plain text passwords are insecure pass on the network. If an attacker can intercept the password you use to insert the SQL statement, they will be able to directly read the password. In addition, the user input string is inserted in the clear to pure SQL statement, also allow an attacker to find it. If you are able to read password, a hacker can. The solution is to use a one-way hash function to the original password encryption coding. Hashing means to convert an input string into another new, unrecognizable function strings. Password encryption expressions add random strings to defend against "dictionary attacks." Do not plaintext password into the SQL query statement. Calculate the hash string in the application code, only use a hash strings in a SQL query.`,
			Case:     "create table test(id int,name varchar(20) not null,password varchar(200)not null)",
			Func:     (*Query4Audit).RuleReadablePasswords,
		},
		"SEC.003": {
			Item:     "SEC.003",
			Severity: "L0",
			Summary:  "Note that when using the backup DELETE / DROP / TRUNCATE other operations",
			Content:  `Back up the data before you perform high-risk operations is very necessary.`,
			Case:     "delete from table where col = 'condition'",
			Func:     (*Query4Audit).RuleDataDrop,
		},
		"SEC.004": {
			Item:     "SEC.004",
			Severity: "L0",
			Summary:  "Find common SQL injection function",
			Content:  `SLEEP(), BENCHMARK(), GET_LOCK(), RELEASE_LOCK()And other functions usually appear in SQL injection statement, will seriously affect database performance.`,
			Case:     "SELECT BENCHMARK(10, RAND())",
			Func:     (*Query4Audit).RuleInjection,
		},
		"STA.001": {
			Item:     "STA.001",
			Severity: "L0",
			Summary:  "'! =' Operator is nonstandard",
			Content:  `"<>" It is not equal to the standard SQL operators.`,
			Case:     "select col1,col2 from tbl where type!=0",
			Func:     (*Query4Audit).RuleStandardINEQ,
		},
		"STA.002": {
			Item:     "STA.002",
			Severity: "L1",
			Summary:  "Library name or table name is recommended after the point of no space",
			Content:  `When db.table table.column format or access the tables or fields, do not add a space dot behind, although this grammatically correct.`,
			Case:     "select col from sakila. film",
			Func:     (*Query4Audit).RuleSpaceAfterDot,
		},
		"STA.003": {
			Item:     "STA.003",
			Severity: "L1",
			Summary:  "Index named non-standard",
			Content:  `It suggests that in general secondary index to idx_ prefixed, unique index to uk_ as a prefix.`,
			Case:     "select col from now where type!=0",
			Func:     (*Query4Audit).RuleIdxPrefix,
		},
		"STA.004": {
			Item:     "STA.004",
			Severity: "L1",
			Summary:  "Do not use characters other than letters, numbers, and underscores when naming",
			Content:  `Start with a letter or an underscore, the name only letters, numbers and underscores. Please unified case, do not use the hump nomenclature. Do not appear in the name continuous underscore '__', making it difficult to identify.`,
			Case:     "CREATE TABLE ` abc` (a int);",
			Func:     (*Query4Audit).RuleStandardName,
		},
		"SUB.001": {
			Item:     "SUB.001",
			Severity: "L4",
			Summary:  "MySQL optimization results in poor subquery",
			Content:  `MySQL each row in the outer query as a dependent sub-query execution sub-queries. This is a common cause of serious performance problems. This may improve in the MySQL 5.6 version, but 5.1 and earlier versions, it is recommended the class were rewritten to query JOIN or LEFT OUTER JOIN.`,
			Case:     "select col1,col2,col3 from table1 where col2 in(select col from table2)",
			Func:     (*Query4Audit).RuleInSubquery,
		},
		"SUB.002": {
			Item:     "SUB.002",
			Severity: "L2",
			Summary:  "If you do not care to repeat the words, it recommends the use of alternative UNION ALL UNION",
			Content:  `And removing duplicate different UNION, UNION ALL allow duplicate tuples. If you do not care about duplicate tuples, use UNION ALL would be a faster option.`,
			Case:     "select teacher_id as id,people_name as name from t1,t2 where t1.teacher_id=t2.people_id union select student_id as id,people_name as name from t1,t2 where t1.student_id=t2.people_id",
			Func:     (*Query4Audit).RuleUNIONUsage,
		},
		"SUB.003": {
			Item:     "SUB.003",
			Severity: "L3",
			Summary:  "Consider using EXISTS instead of DISTINCT subquery",
			Content:  `DISTINCT keyword to remove duplicate in the sorted tuple. Instead, consider using a subquery with EXISTS keywords, you can avoid returning the entire table.`,
			Case:     "SELECT DISTINCT c.c_id, c.c_name FROM c,e WHERE e.c_id = c.c_id",
			Func:     (*Query4Audit).RuleDistinctJoinUsage,
		},
		// TODO: 5.6 With semi join in but also to turn into what exists?
		// Use EXISTS instead of IN to check existence of data.
		// http://www.winwire.com/25-tips-to-improve-sql-query-performance/
		"SUB.004": {
			Item:     "SUB.004",
			Severity: "L3",
			Summary:  "Implementation plan nesting depth is too deep connection",
			Content:  `MySQL optimization results in poor sub-queries, MySQL each row in the outer query as a dependent sub-query execution sub-queries. This is a common cause of serious performance problems.`,
			Case:     "SELECT * from tb where id in (select id from (select id from tb))",
			Func:     (*Query4Audit).RuleSubqueryDepth,
		},
		// SUB.005灵感来自 https://blog.csdn.net/zhuocr/article/details/61192418
		"SUB.005": {
			Item:     "SUB.005",
			Severity: "L8",
			Summary:  "Subquery does not support LIMIT",
			Content:  `The current version of MySQL does not support 'LIMIT & IN / ALL / ANY / SOME' in the sub-queries.`,
			Case:     "SELECT * FROM staff WHERE name IN (SELECT NAME FROM customer ORDER BY name LIMIT 1)",
			Func:     (*Query4Audit).RuleSubQueryLimit,
		},
		"SUB.006": {
			Item:     "SUB.006",
			Severity: "L2",
			Summary:  "Not recommended for use in sub-query function",
			Content:  `MySQL each row in the outer query as a query execution dependency subset subquery, if the function is in a subquery, even semi-join query is difficult to perform efficient. Subquery may be rewritten as OUTER JOIN statement and filters the data connection conditions.`,
			Case:     "SELECT * FROM staff WHERE name IN (SELECT max(NAME) FROM customer)",
			Func:     (*Query4Audit).RuleSubQueryFunctions,
		},
		"SUB.007": {
			Item:     "SUB.007",
			Severity: "L2",
			Summary:  "UNION joint inquiry with the outer limit of LIMIT output, it is also recommended to add inner query output limit LIMIT",
			Content:  `MySQL may not be from outer limits "pushed down" to the inner layer, which makes the original limit who can restrict partial returns results could not be applied to the optimization of the inner query. For example: (SELECT * FROM tb1 ORDER BY name) UNION ALL (SELECT * FROM tb2 ORDER BY name) LIMIT 20; MySQL result will be two sub-queries in a temporary table, and then remove the 20 results can be obtained by two Add LIMIT 20 sub-query data to reduce temporary tables. (SELECT * FROM tb1 ORDER BY name LIMIT 20) UNION ALL (SELECT * FROM tb2 ORDER BY name LIMIT 20) LIMIT 20;`,
			Case:     "(SELECT * FROM tb1 ORDER BY name LIMIT 20) UNION ALL (SELECT * FROM tb2 ORDER BY name LIMIT 20) LIMIT 20;",
			Func:     (*Query4Audit).RuleUNIONLimit,
		},
		"TBL.001": {
			Item:     "TBL.001",
			Severity: "L4",
			Summary:  "Not recommended partition table",
			Content:  `Not recommended partition table`,
			Case:     "CREATE TABLE trb3(id INT, name VARCHAR(50), purchased DATE) PARTITION BY RANGE(YEAR(purchased)) (PARTITION p0 VALUES LESS THAN (1990), PARTITION p1 VALUES LESS THAN (1995), PARTITION p2 VALUES LESS THAN (2000), PARTITION p3 VALUES LESS THAN (2005) );",
			Func:     (*Query4Audit).RulePartitionNotAllowed,
		},
		"TBL.002": {
			Item:     "TBL.002",
			Severity: "L4",
			Summary:  "Please choose the right storage engine for the table",
			Content:  `Recommended using the recommended storage engine, such as when construction of the table or modify the table storage engine:` + strings.Join(common.Config.AllowEngines, ","),
			Case:     "create table test(`id` int(11) NOT NULL AUTO_INCREMENT)",
			Func:     (*Query4Audit).RuleAllowEngine,
		},
		"TBL.003": {
			Item:     "TBL.003",
			Severity: "L8",
			Summary:  "DUAL named table to have a special meaning in the database",
			Content:  `DUAL table is a virtual table, no need to create to use, and does not advise the service DUAL named to the table.`,
			Case:     "create table dual(id int, primary key (id));",
			Func:     (*Query4Audit).RuleCreateDualTable,
		},
		"TBL.004": {
			Item:     "TBL.004",
			Severity: "L2",
			Summary:  "AUTO_INCREMENT initial value table is not 0",
			Content:  `AUTO_INCREMENT is not 0 result in data voids.`,
			Case:     "CREATE TABLE tbl (a int) AUTO_INCREMENT = 10;",
			Func:     (*Query4Audit).RuleAutoIncrementInitNotZero,
		},
		"TBL.005": {
			Item:     "TBL.005",
			Severity: "L4",
			Summary:  "Please use the recommended character set",
			Content:  `Table character set allows only to '` + strings.Join(common.Config.AllowCharsets, ",") + "'",
			Case:     "CREATE TABLE tbl (a int) DEFAULT CHARSET = latin1;",
			Func:     (*Query4Audit).RuleTableCharsetCheck,
		},
		"TBL.006": {
			Item:     "TBL.006",
			Severity: "L1",
			Summary:  "Not recommended View",
			Content:  `Not recommended View`,
			Case:     "create view v_today (today) AS SELECT CURRENT_DATE;",
			Func:     (*Query4Audit).RuleForbiddenView,
		},
		"TBL.007": {
			Item:     "TBL.007",
			Severity: "L1",
			Summary:  "We do not recommend the use of temporary table",
			Content:  `We do not recommend the use of temporary table`,
			Case:     "CREATE TEMPORARY TABLE `work` (`time` time DEFAULT NULL) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleForbiddenTempTable,
		},
		"TBL.008": {
			Item:     "TBL.008",
			Severity: "L4",
			Summary:  "Use recommended COLLATE",
			Content:  `COLLATE only set to '` + strings.Join(common.Config.AllowCollates, ",") + "'",
			Case:     "CREATE TABLE tbl (a int) DEFAULT COLLATE = latin1_bin;",
			Func:     (*Query4Audit).RuleTableCharsetCheck,
		},
	}
}

// IsIgnoreRule determine whether the filter rule
// XXX * Support // prefix matching, OK filter rule can not be set
func IsIgnoreRule(item string) bool {

	for _, ir := range common.Config.IgnoreRules {
		ir = strings.Trim(ir, "*")
		if strings.HasPrefix(item, ir) && ir != "OK" && ir != "" {
			common.Log.Debug("IsIgnoreRule: %s", item)
			return true
		}
	}
	return false
}

// InBlackList determine whether a request blacklist in
// If returns true, indicates that no assessment
// Note that no fingerprints done to determine whether treatment outside of this function with fingerprint
func InBlackList(sql string) bool {
	in := false
	for _, r := range common.BlackList {
		if sql == r {
			in = true
			break
		}
		re, err := regexp.Compile("(?i)" + r)
		if err == nil {
			if re.FindString(sql) != "" {
				common.Log.Debug("InBlackList: true, regexp: %s, sql: %s", "(?i)"+r, sql)
				in = true
				break
			}
			common.Log.Debug("InBlackList: false, regexp: %s, sql: %s", "(?i)"+r, sql)
		}
	}
	return in
}

// FormatSuggest 格式化输出优化建议
func FormatSuggest(sql string, currentDB string, format string, suggests ...map[string]Rule) (map[string]Rule, string) {
	common.Log.Debug("FormatSuggest, Query: %s", sql)
	var fingerprint, id string
	var buf []string
	var score = 100
	type Result struct {
		ID          string
		Fingerprint string
		Sample      string
		Suggest     map[string]Rule
	}

	// 生成指纹和ID
	if sql != "" {
		fingerprint = query.Fingerprint(sql)
		id = query.Id(fingerprint)
	}

	// 合并重复的建议
	suggest := make(map[string]Rule)
	for _, s := range suggests {
		for item, rule := range s {
			suggest[item] = rule
		}
	}
	suggest = MergeConflictHeuristicRules(suggest)

	// 是否忽略显示OK建议，测试的时候大家都喜欢看OK，线上跑起来的时候OK太多反而容易看花眼
	ignoreOK := false
	for _, r := range common.Config.IgnoreRules {
		if "OK" == r {
			ignoreOK = true
		}
	}

	// 先保证suggest中有元素，然后再根据ignore配置删除不需要的项
	if len(suggest) < 1 {
		suggest = map[string]Rule{"OK": HeuristicRules["OK"]}
	}
	if ignoreOK || len(suggest) > 1 {
		delete(suggest, "OK")
	}
	for k := range suggest {
		if IsIgnoreRule(k) {
			delete(suggest, k)
		}
	}
	common.Log.Debug("FormatSuggest, format: %s", format)
	switch format {
	case "json":
		buf = append(buf, formatJSON(sql, currentDB, suggest))

	case "text":
		for item, rule := range suggest {
			buf = append(buf, fmt.Sprintln("Query: ", sql))
			buf = append(buf, fmt.Sprintln("ID: ", id))
			buf = append(buf, fmt.Sprintln("Item: ", item))
			buf = append(buf, fmt.Sprintln("Severity: ", rule.Severity))
			buf = append(buf, fmt.Sprintln("Summary: ", rule.Summary))
			buf = append(buf, fmt.Sprintln("Content: ", rule.Content))
		}
	case "lint":
		for item, rule := range suggest {
			// lint 中无需关注 OK 和 EXP
			if item != "OK" && !strings.HasPrefix(item, "EXP") {
				buf = append(buf, fmt.Sprintf("%s %s", item, rule.Summary))
			}
		}

	case "markdown", "html", "explain-digest", "duplicate-key-checker":
		if sql != "" && len(suggest) > 0 {
			switch common.Config.ExplainSQLReportType {
			case "fingerprint":
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", fingerprint))
			case "sample":
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", sql))
			default:
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", ast.Pretty(sql, format)))
			}
		}
		// MySQL
		common.Log.Debug("FormatSuggest, start of sortedMySQLSuggest")
		var sortedMySQLSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "ERR") {
				if suggest[item].Content == "" {
					delete(suggest, item)
				} else {
					sortedMySQLSuggest = append(sortedMySQLSuggest, item)
				}
			}
		}
		sort.Strings(sortedMySQLSuggest)
		if len(sortedMySQLSuggest) > 0 {
			buf = append(buf, "## MySQL execute failed\n")
		}
		for _, item := range sortedMySQLSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			score = 0
			delete(suggest, item)
		}

		// Explain
		common.Log.Debug("FormatSuggest, start of sortedExplainSuggest")
		if suggest["EXP.000"].Item != "" {
			buf = append(buf, fmt.Sprintln("## ", suggest["EXP.000"].Summary))
			buf = append(buf, fmt.Sprintln(suggest["EXP.000"].Content))
			buf = append(buf, fmt.Sprint(suggest["EXP.000"].Case, "\n"))
			delete(suggest, "EXP.000")
		}
		var sortedExplainSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "EXP") {
				sortedExplainSuggest = append(sortedExplainSuggest, item)
			}
		}
		sort.Strings(sortedExplainSuggest)
		for _, item := range sortedExplainSuggest {
			buf = append(buf, fmt.Sprintln("### ", suggest[item].Summary))
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			buf = append(buf, fmt.Sprint(suggest[item].Case, "\n"))
		}

		// Profiling
		common.Log.Debug("FormatSuggest, start of sortedProfilingSuggest")
		var sortedProfilingSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "PRO") {
				sortedProfilingSuggest = append(sortedProfilingSuggest, item)
			}
		}
		sort.Strings(sortedProfilingSuggest)
		if len(sortedProfilingSuggest) > 0 {
			buf = append(buf, "## Profiling信息\n")
		}
		for _, item := range sortedProfilingSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			delete(suggest, item)
		}

		// Trace
		common.Log.Debug("FormatSuggest, start of sortedTraceSuggest")
		var sortedTraceSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "TRA") {
				sortedTraceSuggest = append(sortedTraceSuggest, item)
			}
		}
		sort.Strings(sortedTraceSuggest)
		if len(sortedTraceSuggest) > 0 {
			buf = append(buf, "## Trace信息\n")
		}
		for _, item := range sortedTraceSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			delete(suggest, item)
		}

		// Index
		common.Log.Debug("FormatSuggest, start of sortedIdxSuggest")
		var sortedIdxSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "IDX") {
				sortedIdxSuggest = append(sortedIdxSuggest, item)
			}
		}
		sort.Strings(sortedIdxSuggest)
		for _, item := range sortedIdxSuggest {
			buf = append(buf, fmt.Sprintln("## ", common.MarkdownEscape(suggest[item].Summary)))
			buf = append(buf, fmt.Sprintln("* **Item:** ", item))
			buf = append(buf, fmt.Sprintln("* **Severity:** ", suggest[item].Severity))
			minus, err := strconv.Atoi(strings.Trim(suggest[item].Severity, "L"))
			if err == nil {
				score = score - minus*5
			} else {
				common.Log.Debug("FormatSuggest, sortedIdxSuggest, strconv.Atoi, Error: ", err)
				score = 0
			}
			buf = append(buf, fmt.Sprintln("* **Content:** ", common.MarkdownEscape(suggest[item].Content)))

			if format == "duplicate-key-checker" {
				buf = append(buf, fmt.Sprintf("* **原建表语句:** \n```sql\n%s\n```\n", suggest[item].Case), "\n\n")
			} else {
				buf = append(buf, fmt.Sprint("* **Case:** ", common.MarkdownEscape(suggest[item].Case), "\n\n"))
			}
		}

		// Heuristic
		common.Log.Debug("FormatSuggest, start of sortedHeuristicSuggest")
		var sortedHeuristicSuggest []string
		for item := range suggest {
			if !strings.HasPrefix(item, "EXP") &&
				!strings.HasPrefix(item, "IDX") &&
				!strings.HasPrefix(item, "PRO") {
				sortedHeuristicSuggest = append(sortedHeuristicSuggest, item)
			}
		}
		sort.Strings(sortedHeuristicSuggest)
		for _, item := range sortedHeuristicSuggest {
			buf = append(buf, fmt.Sprintln("##", suggest[item].Summary))
			if item == "OK" {
				continue
			}
			buf = append(buf, fmt.Sprintln("* **Item:** ", item))
			buf = append(buf, fmt.Sprintln("* **Severity:** ", suggest[item].Severity))
			minus, err := strconv.Atoi(strings.Trim(suggest[item].Severity, "L"))
			if err == nil {
				score = score - minus*5
			} else {
				common.Log.Debug("FormatSuggest, sortedHeuristicSuggest, strconv.Atoi, Error: ", err)
				score = 0
			}
			buf = append(buf, fmt.Sprintln("* **Content:** ", common.MarkdownEscape(suggest[item].Content)))
			// buf = append(buf, fmt.Sprint("* **Case:** ", common.MarkdownEscape(suggest[item].Case), "\n\n"))
		}

	default:
		common.Log.Debug("report-type: %s", format)
		buf = append(buf, fmt.Sprintln("Query: ", sql))
		for _, rule := range suggest {
			buf = append(buf, pretty.Sprint(rule))
		}
	}

	// 打分
	var str string
	switch common.Config.ReportType {
	case "markdown", "html":
		if len(buf) > 1 {
			str = buf[0] + "\n" + common.Score(score) + "\n\n" + strings.Join(buf[1:], "\n")
		}
	default:
		str = strings.Join(buf, "\n")
	}

	return suggest, str
}

// JSONSuggest json format suggestion
type JSONSuggest struct {
	ID             string   `json:"ID"`
	Fingerprint    string   `json:"Fingerprint"`
	Score          int      `json:"Score"`
	Sample         string   `json:"Sample"`
	Explain        []Rule   `json:"Explain"`
	HeuristicRules []Rule   `json:"HeuristicRules"`
	IndexRules     []Rule   `json:"IndexRules"`
	Tables         []string `json:"Tables"`
}

func formatJSON(sql string, db string, suggest map[string]Rule) string {
	var id, fingerprint, result string

	fingerprint = query.Fingerprint(sql)
	id = query.Id(fingerprint)

	// Score
	score := 100
	for item := range suggest {
		l, err := strconv.Atoi(strings.TrimLeft(suggest[item].Severity, "L"))
		if err != nil {
			common.Log.Error("formatJSON strconv.Atoi error: %s, item: %s, serverity: %s", err.Error(), item, suggest[item].Severity)
		}
		score = score - l*5
	}
	if score < 0 {
		score = 0
	}

	sug := JSONSuggest{
		ID:          id,
		Fingerprint: fingerprint,
		Sample:      sql,
		Tables:      ast.SchemaMetaInfo(sql, db),
		Score:       score,
	}

	// Explain info
	var sortItem []string
	for item := range suggest {
		if strings.HasPrefix(item, "EXP") {
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.Explain = append(sug.Explain, suggest[i])
	}
	sortItem = make([]string, 0)

	// Index advisor
	for item := range suggest {
		if strings.HasPrefix(item, "IDX") {
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.IndexRules = append(sug.IndexRules, suggest[i])
	}
	sortItem = make([]string, 0)

	// Heuristic rules
	for item := range suggest {
		if !strings.HasPrefix(item, "EXP") && !strings.HasPrefix(item, "IDX") {
			if strings.HasPrefix(item, "ERR") && suggest[item].Content == "" {
				continue
			}
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.HeuristicRules = append(sug.HeuristicRules, suggest[i])
	}
	sortItem = make([]string, 0)

	js, err := json.MarshalIndent(sug, "", "  ")
	if err == nil {
		result = fmt.Sprint(string(js))
	} else {
		common.Log.Error("formatJSON json.Marshal Error: %v", err)
	}
	return result
}

// ListHeuristicRules 打印支持的启发式规则，对应命令行参数-list-heuristic-rules
func ListHeuristicRules(rules ...map[string]Rule) {
	switch common.Config.ReportType {
	case "json":
		js, err := json.MarshalIndent(rules, "", "  ")
		if err == nil {
			fmt.Println(string(js))
		}
	default:
		fmt.Print("# 启发式规则建议\n\n[toc]\n\n")
		for _, r := range rules {
			delete(r, "OK")
			for _, item := range common.SortedKey(r) {
				fmt.Print("## ", common.MarkdownEscape(r[item].Summary),
					"\n\n* **Item**:", r[item].Item,
					"\n* **Severity**:", r[item].Severity,
					"\n* **Content**:", common.MarkdownEscape(r[item].Content),
					"\n* **Case**:\n\n```sql\n", r[item].Case, "\n```\n")
			}
		}
	}
}

// ListTestSQLs 打印测试用的SQL，方便测试，对应命令行参数-list-test-sqls
func ListTestSQLs() {
	for _, sql := range common.TestSQLs {
		fmt.Println(sql)
	}
}
