/**
 * @name Sensitive Info In Stack Memory
 * @description Sensitive data stored in stack-allocated memory without cleanup
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id cpp/sensitive_info_in_stack_memory
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
from LocalVariable v
where v.getType().getName().toLowerCase().matches("%password%")
  or v.getType().getName().toLowerCase().matches("%credential%")
  or v.getName().toLowerCase().matches("%password%")
  or v.getName().toLowerCase().matches("%pwd%")
select v, "Sensitive data stored in stack-allocated memory without cleanup"
