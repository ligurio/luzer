--[[
-- TODO:
-- https://in2test.lsi.uniovi.es/sqlmutation/
-- https://cosette.cs.washington.edu/
-- https://www.cs.cmu.edu/~15811/papers/db.pdf
-- https://github.com/uwdb/Cosette
-- https://github.com/sqlancer/sqlancer
-- https://github.com/Practical-Formal-Methods/queryFuzz
-- https://github.com/PSU-Security-Universe/sqlright
--
-- https://github.com/PingCAP-QE/go-sqlancer/tree/master/pkg
-- https://github.com/tarantool/sqlparser
--
-- Corpus:
--   - https://github.com/PSU-Security-Universe/sqlright/tree/main/SQLite/docker/fuzz_root/inputs
--
-- Automatic Test Generation for Mutation Testing on Database Applications
--
-- Sqlsmith
--
-- An Experimental Case Study to Applying Mutation Analysis for SQL Queries
--
-- SQLMutation - Generation of mutants for testing SQL database queries
--
-- Generating test data for killing SQL mutants: A constraint-based approach
--
]]

local lpeg = require("lpeg")
local locale = lpeg.locale
local P = lpeg.P
--local R = lpeg.R
--local S = lpeg.S
local V = lpeg.V
local C = lpeg.C
--local Cb = lpeg.Cb
--local Cc = lpeg.Cc
--local Cf = lpeg.Cf
--local Cg = lpeg.Cg
--local Cp = lpeg.Cp
--local Cs = lpeg.Cs
--local Ct = lpeg.Ct
--local Cmt = lpeg.Cmt

---
-- Returns a pattern which matches the literal string caselessly.
--
-- @param literal A literal string to match case-insensitively.
-- @return An LPeg pattern.
--
local function caseless(literal)
    local caseless = lpeg.Cf((lpeg.P(1) / function (a)
            return lpeg.S(a:lower() .. a:upper())
        end)^1, function (a, b)
            return a * b
        end)
    return assert(caseless:match(literal))
end

local K = caseless

--- Simple printf-style function.
local function printf(...)
    print(string.format(...))
end

---
-- Adds hooks to a grammar to print debugging information.
--
-- Debugging LPeg grammars can be difficult. Calling this function on your
-- grammmar will cause it to print ENTER and LEAVE statements for each rule, as
-- well as position and subject after each successful rule match.
--
-- For convenience, the modified grammar is returned; a copy is not made
-- though, and the original grammar is modified as well.
--
-- Credits: http://lua-users.org/lists/lua-l/2009-10/msg00774.html
--
-- @param grammar The LPeg grammar to modify
-- @param printer A printf-style formatting printer function to use.
--                Default: stdnse.debug1
-- @return The modified grammar.
--
local function debug(grammar, printer)
    printer = printer or printf
    for k, p in pairs(grammar) do
        local enter = lpeg.Cmt(lpeg.P(true), function(s, p, ...)
            printer("ENTER %s", k)
            return p
        end)
        local leave = lpeg.Cmt(lpeg.P(true), function(s, p, ...)
            printer("LEAVE %s", k)
            return p
        end) * (lpeg.P("k") - lpeg.P "k")
        grammar[k] = lpeg.Cmt(enter * p + leave, function(s, p, ...)
            printer("---%s---", k)
            printer("pos: %d, [%s]", p, s:sub(1, p-1))
            return p
        end)
    end

    return grammar
end

local mysql = locale {

  V "sql_stmt",

  sql_stmt = V "space"^0 * (
                V "select_stmt" +
                V "update_stmt") *
             V "space"^0 * (
                P ";" + -1),

  select_stmt = K "SELECT" *
                V "space"^0 *
                V "select_expr_list" *
                V "space"^0 *
                V "from_clause"^-1,

  from_clause = K "FROM" *
                V "space"^0 *
                V "table_references" *
                V "space"^0 *
                V "where_clause"^-1,

  where_clause = K "WHERE" *
                 V "space"^0 *
                 V "where_condition",

  update_stmt = K "UPDATE" *
                V "space"^0 *
                P "t set id = 1", -- TODO

  select_expr_list = V "select_expr" *
                     V "space"^0 *
                     (P "," *
                      V "space"^0 *
                      V "select_expr")^0,

  select_expr = P "*" + (
                    V "table_name" *
                    P "." *
                    P "*") +
                V "column_item",  -- TODO sql function

  -- TODO
  table_references = P "table1",

  where_condition = V "expr",

  column_item = (V "expr" *
                 V "space"^0 *
                 K "AS" *
                 V "space"^0 *
                 V "column_alias" +
                 V "expr" *
                 V "space"^0 *
                 V "column_alias" +
                 V "expr"),

  -- See expr in http://www.sqlite.org/lang_select.html
  -- See http://dev.mysql.com/doc/refman/5.5/en/expressions.html
  expr = (V "atomic_expr" * (V "space"^0 *
              V "binary_operator" *
              V "space"^0 *
              V "expr"
          )^-1),

  atomic_expr = (V "literal_value" +
                 V "variable" +
                 V "column_expr" +
                 V "unary_operator" *
                 V "space"^0 *
                 V "expr"),

  column_expr = (V "schema_name" *
                 P "." *
                 V "table_name" *
                 P "." *
                 V "column_name" +
                 V "table_name" *
                 P "." *
                 V "column_name" +
                 V "column_name"),

  schema_name = V "name",
  column_alias = V "name",
  column_name = V "name",
  table_name = V "name",

  binary_operator = (K "OR" +
                     P "||" +
                     K "XOR" +
                     K "AND" +
                     P "&&"
                     ) + V "comparison_operator",

  comparison_operator = (P "=" +
                         P ">=" +
                         P ">" +
                         P "<=" +
                         P "<" +
                         P "<>" +
                         P "!="),

  unary_operator = (K "NOT" +
                    P "!"),

  variable = V "name",

  literal_value = V "numeric_literal" +
                  V "string_literal" +
                  P "NULL" +
                  P "CURRENT_TIME" +
                  P "CURRENT_DATE" +
                  P "CURRENT_TIMESTAMP",  -- see http://dev.mysql.com/doc/refman/5.5/en/literals.html

  -- not enough, see http://dev.mysql.com/doc/refman/5.5/en/number-literals.html
  numeric_literal = V "digit"^1,

  string_literal = (P "_" *
                    V "charset_name" +
                    caseless "n")^-1 * V "real_string_literal",

  -- not enough, see http://dev.mysql.com/doc/refman/5.5/en/string-literals.html
  real_string_literal = P '"' * (1 - P '"')^0 * P '"' + P "'" * (1 - P "'")^0 * P "'",

  charset_name = V "name",

  name = P "`"^-1 * ( V "alnum" + P "_" )^1 * P "`"^-1,
}

local mysql_grammar = P(C(mysql))

local res = mysql_grammar:match("SELECT * FROM table1 WHERE a = 1")
if res then
    print(res)
else
    local mysql_grammar_debug = P(debug(mysql))
    res = mysql_grammar_debug:match("SELECT * FROM table1 WHERE a = 1")
    print(res)
end
