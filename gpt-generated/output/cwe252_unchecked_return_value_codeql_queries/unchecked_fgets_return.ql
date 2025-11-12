/**
 * @name Unchecked Fgets Return
 * @description Return value of fgets not checked for NULL
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/unchecked_fgets_return
 * @tags security
 *       external/cwe/cwe-252
 */

import cpp
import cpp

from FunctionCall fc
where fc.getTarget().getName() = "fgets"
  and not exists(ExprInVoidContext eivc | eivc.getExpr() = fc)
  and not exists(IfStmt is | is.getCondition() = fc)
  and not exists(IfStmt is |
    is.getCondition().(BinaryOperation).getAnOperand*() = fc
  )
select fc, "Return value of fgets not checked for NULL"
