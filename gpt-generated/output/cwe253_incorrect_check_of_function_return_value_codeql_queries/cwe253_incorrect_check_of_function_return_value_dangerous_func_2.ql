/**
 * @name Cwe253 Incorrect Check Of Function Return Value Dangerous Func 2
 * @description Potentially dangerous function scanf detected.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe253_incorrect_check_of_function_return_value_dangerous_func_2
 * @tags security
 *       external/cwe/cwe-253
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "scanf"
select fc, "Potentially dangerous function scanf detected."
