#  77.30-80.40.ps1
#  


. .\src\functions.ps1
try {
    . .\conf\config.ps1
} catch {
    Write-Host "config error -- $_" -ForegroundColor Red
    exit 1
}

$r80_40_layer_name =        $config['R80.40_layer_name']
$r80_40_start_rule_number = $config['R80.40_start_rule_number']
$special_date =             $config['special_date']
$firewall_name =            $config['firewall_name']
$vpn_name =                 $config['vpn_name']
$placeholder =              $config['placeholder']
$color =                    $config['color']


Write-Host "Импорт сетевых объектов R80.40 из файла 'network_objects.csv'" -NoNewline
Write-Host "`r`t`t`t`t`t`t`t`t`t`t..." -NoNewline
try {
    $network_objects_80_40 = Import-Csv -path '.\input\from_80.40\network_objects.csv'
} catch {
    Write-Host "`nimport 'network_objects.csv' error -- $_" -ForegroundColor Red
    exit 1
}
Write-Host "`r`t`t`t`t`t`t`t`t`t`tЗАВЕРШЕН"
$network_objects_80_40_names = $network_objects_80_40 | ForEach-Object {$_.Name}

Write-Host "Импорт сервисов R80.40 из файла 'services.csv'`t" -NoNewline
Write-Host "`r`t`t`t`t`t`t`t`t`t`t..." -NoNewline
try {
    $services_80_40 = Import-Csv -path '.\input\from_80.40\services.csv'
} catch {
    Write-Host "`nimport 'services.csv' error -- $_" -ForegroundColor Red
    exit 1
}
Write-Host "`r`t`t`t`t`t`t`t`t`t`tЗАВЕРШЕН"
$services_80_40_names = $services_80_40 | ForEach-Object {$_.Name}

Write-Host "Импорт объектов времени R80.40 из файла 'time_objects.csv'" -NoNewline
Write-Host "`r`t`t`t`t`t`t`t`t`t`t..." -NoNewline
try {
    $time_objects_80_40 = Import-Csv -path '.\input\from_80.40\time_objects.csv'
} catch {
    Write-Host "`nimport 'services.csv' error -- $_" -ForegroundColor Red
    exit 1
}
Write-Host "`r`t`t`t`t`t`t`t`t`t`tЗАВЕРШЕН"
$time_objects_80_40_names = $time_objects_80_40 | ForEach-Object {$_.Name}

Write-Host "Импорт сетевых объектов R77.30 из файла 'network_objects.xml'" -NoNewline
Write-Host "`r`t`t`t`t`t`t`t`t`t`t..." -NoNewline
try {
    $raw_network_objects_77_30 = Get-Content '.\input\from_77.30\network_objects.xml' -ErrorAction Stop
    [xml]$xml_network_objects_77_30 = $raw_network_objects_77_30
} catch {
    Write-Host "`nimport 'network_objects.xml' error -- $_" -ForegroundColor Red
    exit 1
}
Write-Host "`r`t`t`t`t`t`t`t`t`t`tЗАВЕРШЕН"

Write-Host "Импорт сервисов R77.30 из файла 'services.xml'" -NoNewline
Write-Host "`r`t`t`t`t`t`t`t`t`t`t..." -NoNewline
try {
    $raw_services_77_30 = Get-Content '.\input\from_77.30\services.xml' -ErrorAction Stop
    [xml]$xml_services_77_30 = $raw_services_77_30
} catch {
    Write-Host "`nimport 'services.xml' error -- $_" -ForegroundColor Red
    exit 1
}
Write-Host "`r`t`t`t`t`t`t`t`t`t`tЗАВЕРШЕН"

$file_access_rules_77_30 = Get-ChildItem -Path '.\input\from_77.30\*' -Include '*_Security_Policy.xml'
$file_name = "$file_access_rules_77_30".Split('\')[-1]
Write-Host "Импорт правил доступа R77.30 из файла '$file_name'" -NoNewline
Write-Host "`r`t`t`t`t`t`t`t`t`t`t..." -NoNewline
try {
    $raw_access_rules_77_30 = Get-Content $file_access_rules_77_30 -ErrorAction Stop
    [xml]$xml_access_rules_77_30 = $raw_access_rules_77_30
} catch {
    Write-Host "`nimport '$file_name' error -- $_" -ForegroundColor Red
    exit 1
}
Write-Host "`r`t`t`t`t`t`t`t`t`t`tЗАВЕРШЕН"

Write-Host


$net_groups =               [ordered]@{}
$net_groups_correct_order = [ordered]@{}
$hosts =                    [ordered]@{}
$nets =                     [ordered]@{}

$network_objects_77_30 = $xml_network_objects_77_30.network_objects.network_object
$num = $network_objects_77_30.count
$i = 1
foreach ($obj in $network_objects_77_30) {
    if ($obj.Class_Name -eq 'network_object_group') {
     #обработка объектов сетевых групп
        $group_name = $obj.Name
        $ggr_without_prefix = @(
            'Blocked_IP'
        )
        if (-not ($group_name.StartsWith('ggr') -or $group_name.StartsWith('gg_') -or ($ggr_without_prefix -contains $group_name))) {
            if (-not ($network_objects_80_40_names -contains $group_name)) {
                $net_groups[$group_name] = Get-NetGroupData $obj
            }
        }
        
    } elseif ($obj.Class_Name -eq 'host_plain') {
     #обработка объектов узлов
        $host_name = $obj.Name
        $gh_without_prefix = @(
            'Log_parser',
            'temp_lip'
        )
        if (-not ($host_name.StartsWith('g_') -or ($gh_without_prefix -contains $host_name))) {
            if (-not ($network_objects_80_40_names -contains $host_name)) {
                $hosts[$host_name] = Get-HostData $obj
            }
        }
        
    } elseif ($obj.Class_Name -eq 'network') {
     #обработка объектов сетей
        $net_name = $obj.Name
        $gn_without_prefix = @(
            'gr_10.24.36.0_27_Len'
        )
        if (-not ($net_name.StartsWith('gn_') -or $net_name.StartsWith('g_') -or ($gn_without_prefix -contains $net_name))) {
            if (-not ($network_objects_80_40_names -contains $net_name)) {
                $nets[$net_name] = Get-NetData $obj
            }
        }
    }
    [int]$percent = 100 * $i / $num
    Write-Host "`rОбработка сетевых объектов R77.30:    $percent%" -NoNewline
    $i += 1
}

foreach ($group_name in $net_groups.Keys) {
    Walk-Trail $group_name $net_groups $net_groups_correct_order
}

$api_call_to_create_net_groups =    Make-API_call_to_create_net_groups $net_groups_correct_order $color
$api_call_to_create_hosts =         Make-API_call_to_create_hosts $hosts $color
$api_call_to_create_nets =          Make-API_call_to_create_nets $nets $color

Write-Host

$service_groups =               [ordered]@{}
$service_groups_correct_order = [ordered]@{}
$tcp_services =                 [ordered]@{}
$udp_services =                 [ordered]@{}

$services_77_30 = $xml_services_77_30.services.service
$num = $services_77_30.count
$i = 1
foreach ($service in $services_77_30) {
    if ($service.Class_Name -eq 'service_group') {
     #обработка групп сервисов
        $group_name = $service.Name
        if (-not ($services_80_40_names -contains $group_name)) {
            $service_groups[$group_name] = Get-ServiceGroupData $service
        }
        
    } elseif ($service.Class_Name -eq 'tcp_service') {
     #обработка сервисов TCP
        $service_name = $service.Name
        $gs_without_prefix = @(
            'gFW1_amon',
            'gFW1_cvp',
            'gFW1_ufp',
            'gtcp-high-ports',
            'tcp_134-140',
            'tcp_1521-1551',
            'tcp_3872',
            'tcp_444-446',
            'tcp_4889'
        )
        if (-not ($service_name.StartsWith('g_') -or ($gs_without_prefix -contains $service_name))) {
            if (-not ($services_80_40_names -contains $service_name)) {
                $tcp_services[$service_name] = Get-TCPserviceData $service
            }
        }
        
    } elseif ($service.Class_Name -eq 'udp_service') {
     #обработка сервисов UDP
        $service_name = $service.Name
        $gs_without_prefix = @(
            'udp_134-140',
            'udp_444-446',
            'wins_old_1512_udp'
        )
        if (-not ($service_name.StartsWith('g_') -or ($gs_without_prefix -contains $service_name))) {
            if (-not ($services_80_40_names -contains $service_name)) {
                $udp_services[$service_name] = Get-UDPserviceData $service
            }
        }
        
    }
    [int]$percent = 100 * $i / $num
    Write-Host "`rОбработка сервисов R77.30:            $percent%" -NoNewline
    $i += 1
}

foreach ($group_name in $service_groups.Keys) {
    Walk-Trail $group_name $service_groups $service_groups_correct_order
}

$api_call_to_create_service_groups =    Make-API_call_to_create_service_groups $service_groups_correct_order $color
$api_call_to_create_tcp_services =      Make-API_call_to_create_tcp_services $tcp_services $color
$api_call_to_create_udp_services =      Make-API_call_to_create_udp_services $udp_services $color

Write-Host

$access_rules = [System.Collections.Generic.List[PSObject]]::new()

$start_rule_number = $config['R77.30_rule_range']['start_rule_number']
$last_rule_number = $config['R77.30_rule_range']['last_rule_number']
$current_rule_number = 0

$rules_77_30 = $xml_access_rules_77_30.fw_policies.fw_policie.rule.rule
$num = $rules_77_30.count
$i = 1
foreach ($rule in $rules_77_30) {
    $current_rule_number = if ($rule.Class_Name -eq 'security_rule') {[int]$rule.Rule_Number} else {($current_rule_number + 0.5)}
    if (($current_rule_number -gt ($start_rule_number - 1)) `
        -and ($current_rule_number -le $last_rule_number)) {
    #обработка заголовков и правил из указанного в конфиге диапазона
        if ($rule.header_text."#cdata-section" -ne $null) {
            $access_rules.Add($rule.header_text."#cdata-section")
            
        } elseif ($rule.Class_Name -eq 'security_rule') {
            $access_rules.Add((Get-RuleData $rule))
        }
    }
    [int]$percent = 100 * $i / $num
    Write-Host "`rОбработка правил доступа R77.30:      $percent%" -NoNewline
    $i += 1
}

$api_call_to_create_access_rules, `
$api_call_to_set_comments, `
$placeholders_in_rules, `
$skipped_rules, `
$rule_map = Make-API_call_to_create_access_rules `
    $access_rules `
    $net_groups_correct_order `
    $hosts `
    $nets `
    $network_objects_80_40_names `
    $service_groups_correct_order `
    $tcp_services `
    $udp_services `
    $services_80_40_names `
    $time_objects_80_40_names `
    $r80_40_layer_name `
    $r80_40_start_rule_number `
    $special_date `
    $firewall_name `
    $vpn_name `
    $placeholder


Write-Host "`n"

Get-ChildItem .\output\ -Recurse | Remove-Item -Recurse -Confirm:$false

$i = 1
if ($api_call_to_create_hosts.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания объектов сетевых узлов ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_hosts"
    SaveTo-File $api_call_to_create_hosts `
                $dir_to_save `
                'api_call_to_create_hosts.txt' `
                500
    Write-Host "`rФайлы с командами API R80.40 для создания объектов сетевых узлов сохранены в каталоге  '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "Объекты сетевых узлов R77.30 уже имеются в R80.40" -ForegroundColor Green
}

if ($api_call_to_create_nets.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания объектов сетей         ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_nets"
    SaveTo-File $api_call_to_create_nets `
                $dir_to_save `
                'api_call_to_create_nets.txt' `
                300
    Write-Host "`rФайлы с командами API R80.40 для создания объектов сетей сохранены в каталоге          '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "Объекты сетей R77.30 уже имеются в R80.40" -ForegroundColor Green
}

if ($api_call_to_create_net_groups.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания объектов сетевых групп ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_net_groups"
    SaveTo-File $api_call_to_create_net_groups `
                $dir_to_save `
                'api_call_to_create_net_groups.txt' `
                500
    Write-Host "`rФайлы с командами API R80.40 для создания объектов сетевых групп сохранены в каталоге  '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "Объекты сетевых групп R77.30 уже имеются в R80.40" -ForegroundColor Green
}

if ($api_call_to_create_tcp_services.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания TCP-сервисов           ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_tcp_services"
    SaveTo-File $api_call_to_create_tcp_services `
                $dir_to_save `
                'api_call_to_create_tcp_services.txt' `
                500
    Write-Host "`rФайлы с командами API R80.40 для создания TCP-сервисов сохранены в каталоге            '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "TCP-сервисы R77.30 уже имеются в R80.40" -ForegroundColor Green
}

if ($api_call_to_create_udp_services.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания UDP-сервисов           ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_udp_services"
    SaveTo-File $api_call_to_create_udp_services `
                $dir_to_save `
                'api_call_to_create_udp_services.txt' `
                500
    Write-Host "`rФайлы с командами API R80.40 для создания UDP-сервисов сохранены в каталоге            '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "UDP-сервисы R77.30 уже имеются в R80.40" -ForegroundColor Green
}

if ($api_call_to_create_service_groups.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания групп сервисов         ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_service_groups"
    SaveTo-File $api_call_to_create_service_groups `
                $dir_to_save `
                'api_call_to_create_service_groups.txt' `
                500
    Write-Host "`rФайлы с командами API R80.40 для создания групп сервисов сохранены в каталоге          '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "Группы сервисов R77.30 уже имеются в R80.40" -ForegroundColor Green
}

if ($api_call_to_create_access_rules.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для создания правил доступа         ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_create_access_rules"
    SaveTo-File $api_call_to_create_access_rules `
                $dir_to_save `
                'api_call_to_create_access_rules.txt' `
                100
    Write-Host "`rФайлы с командами API R80.40 для создания правил доступа сохранены в каталоге          '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "Отсутствуют команды API R80.40 для создания правил доступа" -ForegroundColor Yellow
}

if ($api_call_to_set_comments.count -gt 0) {
    Write-Host "Сохранение команд API R80.40 для добавления комментариев         ..."  -NoNewline
    $dir_to_save = ".\output\0${i}_api_call_to_set_comments"
    SaveTo-File $api_call_to_set_comments `
                $dir_to_save `
                'api_call_to_set_comments.txt' `
                500
    Write-Host "`rФайлы с командами API R80.40 для добавления комментариев сохранены в каталоге          '$dir_to_save'" -ForegroundColor Green
    $i += 1
} else {
    Write-Host "Отсутствуют команды API R80.40 для добавления комментариев" -ForegroundColor Yellow
}

if ($placeholders_in_rules.count -gt 0) {
    Write-Host "Сохранение данных об используемых placeholders                   ..."  -NoNewline
    $file_to_save = ".\output\placeholders_in_rules.txt"
    $placeholders_in_rules | ForEach-Object{ Add-Content $file_to_save -Value $_ -Encoding UTF8 }
    Write-Host "`rДанные об используемых placeholders сохранены в файле                                  '$file_to_save'" -ForegroundColor Green
    $i += 1
}

if ($skipped_rules.count -gt 0) {
    Write-Host "Сохранение данных о пропущенных правилах                         ..."  -NoNewline
    $file_to_save = ".\output\skipped_rules.txt"
    $skipped_rules | ForEach-Object{ Add-Content $file_to_save -Value $_ -Encoding UTF8 }
    Write-Host "`rДанные о пропущенных правилах сохранены в файле                                        '$file_to_save'" -ForegroundColor Green
    $i += 1
}

if ($rule_map.count -gt 0) {
    Write-Host "Сохранение данных о соотвтетсвии правил                          ..."  -NoNewline
    $file_to_save = ".\output\rule_map.txt"
    $rule_map | ForEach-Object{ Add-Content $file_to_save -Value $_ -Encoding UTF8 }
    Write-Host "`rДанные о соотвтетсвии правил сохранены в файле                                         '$file_to_save'" -ForegroundColor Green
    $i += 1
}
