#!/bin/bash

#cmdline=$(cat /proc/cmdline)
cmdline="BOOT_IMAGE=/boot/vmlinuz-4.7.5 root=UUID=1781d1d7-9446-4424-9fc9-1f86cde29643 ro quiet splash ima_appraise=fix"
cmdline+=" "

ima_message=$(journalctl -b | grep "kernel: IMA: policy update completed")
echo $ima_message
echo $cmdline 

# 정규표현식
re_enforce="\s+ima_appraise=fix\s+"
re_off="\s+ima=off\s+"
re_policy="IMA: policy update completed"

if [[ $ima_message =~ $re_policy ]]; then
	echo "Policy"
fi

if [[ $cmdline =~ $re_enforce && ! $cmdline =~ $re_off ]]; then
	echo "Activated"
else
	echo "Deactivated"
fi
