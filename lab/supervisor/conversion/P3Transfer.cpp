#include "P3Transfer.hpp"
namespace gb {
bool P3LimitsCurrent(HANDLE job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    return QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr) &&
        limits.BasicLimitInformation.LimitFlags == P3Flags && limits.BasicLimitInformation.ActiveProcessLimit == 1 &&
        limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart == P3Cpu && limits.ProcessMemoryLimit == P3Memory &&
        QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr) &&
        accounting.ActiveProcesses == 1;
}
}
