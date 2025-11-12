/**
 * @name Cwe242 Use Of Inherently Dangerous Function Dangerous Func 1
 * @description Use of fgets - ensure proper buffer size and null termination.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe242_use_of_inherently_dangerous_function_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-242
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "fgets"
select fc, "Use of fgets - ensure proper buffer size and null termination."
