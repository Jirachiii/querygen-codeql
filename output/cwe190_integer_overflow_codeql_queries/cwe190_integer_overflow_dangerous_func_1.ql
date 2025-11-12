/**
 * @name Cwe190 Integer Overflow Dangerous Func 1
 * @description Potentially dangerous function fscanf detected.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe190_integer_overflow_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-190
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "fscanf"
select fc, "Potentially dangerous function fscanf detected."
