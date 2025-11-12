/**
 * @name Cwe364 Signal Handler Race Condition Dangerous Func 1
 * @description Potentially dangerous function scanf detected.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe364_signal_handler_race_condition_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-364
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "scanf"
select fc, "Potentially dangerous function scanf detected."
