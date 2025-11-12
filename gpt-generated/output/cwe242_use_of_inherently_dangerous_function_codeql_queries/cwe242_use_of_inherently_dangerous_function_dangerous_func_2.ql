/**
 * @name Cwe242 Use Of Inherently Dangerous Function Dangerous Func 2
 * @description Potentially dangerous function scanf detected.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe242_use_of_inherently_dangerous_function_dangerous_func_2
 * @tags security
 *       external/cwe/cwe-242
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "scanf"
select fc, "Potentially dangerous function scanf detected."
