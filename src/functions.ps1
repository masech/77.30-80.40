#  functions.ps1
#  


function Check-Date {
    param(
        [string]$date,
        [hashtable]$special_date
    )

    $result = @{
        'result' =              "undefined";
        'date_name' =           $date;
        'date_value_string' =   $null
    }

    if ($date -in $special_date.Keys) {
        $dateToCheck = $special_date[$date]
    } else {
        $dateToCheck = $date
    }
    
    $matchingDateWithDots = ''
    if ($dateToCheck -match "\d\d\.\d\d\.\d\d\d\d") {
        $matchingDateWithDots = $matches[0]
    } elseif ($dateToCheck -match "\d\d\.\d\d\.\d\d") {
        $matchingDateWithDots = $matches[0]
    } elseif ($dateToCheck -match "\d\d\d\d\d\d\d\d") {
        $tmpDateWithDot = $matches[0].Insert(2, '.')
        $matchingDateWithDots = $tmpDateWithDot.Insert(5, '.')
    } elseif ($dateToCheck -match "\d\d\d\d\d\d") {
        $tmpDateWithDot = $matches[0].Insert(2, '.')
        $matchingDateWithDots = $tmpDateWithDot.Insert(5, '.')
    }
    
    if ($matchingDateWithDots) {
        $now_date = (Get-Date).Date
        try {
            $expiration_date = Get-Date -Date $matchingDateWithDots
        } catch {
            return $result
        }
        if ($expiration_date -ge $now_date) {
            $result = @{
                'result' =              "unexpired";
                'date_name' =           $date;
                'date_value_string' =   Get-Date -Date $expiration_date -Format "yyyy-MM-dd"
            }
        } else {
            $result = @{
                'result' =              "expired";
                'date_name' =           $date;
                'date_value_string' =   $null
            }
        }
    }
    return $result
}


function Make-API_call_to_create_access_rules {
    param(
        $access_rules,
        $net_groups, 
        $hosts,
        $nets,
        $network_objects_80_40_names,
        $service_groups,
        $tcp_services,
        $udp_services,
        $services_80_40_names,
        $time_objects_80_40_names,
        $r80_40_layer_name,
        $r80_40_start_rule_number,
        $special_date,
        $firewall_name,
        $vpn_name,
        $placeholder
    )
    
    $src_dst_placeholder = $placeholder['src/dst_field']
    $service_placeholder = $placeholder['service_field']
    
    $api_call_to_create_access_rules = [System.Collections.Generic.List[string]]::new()
    $api_call_to_set_comments = [System.Collections.Generic.List[string]]::new()
    $placeholders_in_rules = [System.Collections.Generic.List[string]]::new()
    $skipped_rules = [System.Collections.Generic.List[string]]::new()
    $rule_map = [System.Collections.Generic.List[string]]::new()
    
    $current_rule_number = 1
    foreach ($rule in $access_rules) {
        if ($rule.GetType() -eq [string]) {
        #формируем команду для создания заголовка
            $api_call_to_create_access_rules.Add("add access-section layer `"$r80_40_layer_name`" position `"bottom`" name `"$rule`"")
            
        } elseif ($rule.GetType() -eq [hashtable]) {
            $r77_30_rule_number = $rule['number']
            if ($rule['time'] -ne 'Any') {
                $date_check = Check-Date $rule['time'] $special_date
            }
            if ($rule['time'] -eq 'Any' `
                -or $date_check['result'] -eq 'unexpired') {
            #формируем команду для создания неистекшего правила
                $r80_40_rule_number = "$r80_40_start_rule_number.$current_rule_number"
                $api_call_to_rule = [System.Collections.Generic.List[string]]@("add access-rule layer `"$r80_40_layer_name`" position `"bottom`"")
                if ($rule['name'].length -gt 0) {
                    $rule_name = $rule['name']
                    $api_call_to_rule.Add("name `"$rule_name`"")
                }
                if ($rule['disabled'] -eq 'true') {
                    $api_call_to_rule.Add("enabled false")
                }
                $replaceable_src = @()
                if ($rule['src'].count -gt 0 `
                    -and -not($rule['src'] -contains 'Any')) {
                #формируем источники (пропускаем если 'Any', т.к. это эначние делается API по умолчанию)
                    $i = 1
                    foreach ($src in $rule['src']) {
                        if ($net_groups.Keys -contains $src `
                            -or $hosts.Keys -contains $src `
                            -or $nets.Keys -contains $src `
                            -or $network_objects_80_40_names -contains $src) {
                        #если объект имеется в R80.40 или ранее учитывался при формировании команд API для создания объектов, то добавляем его в поле источника
                            $api_call_to_rule.Add("source.$i `"$src`"")
                            $i += 1
                        } else {
                        #иначе заменяем объект плэйсхолдером
                            if ($replaceable_src.count -eq 0) {
                                $api_call_to_rule.Add("source.$i `"$src_dst_placeholder`"")
                                $i += 1
                            }
                            $replaceable_src += $src
                        }
                    }
                }
                if ($rule['src_negate'] -eq 'not in') {
                    $api_call_to_rule.Add("source-negate true")
                }
                $replaceable_dst = @()
                if ($rule['dst'].count -gt 0 `
                    -and -not($rule['dst'] -contains 'Any')) {
                #формируем получателей (пропускаем если 'Any', т.к. это эначние делается API по умолчанию)
                    $i = 1
                    foreach ($dst in $rule['dst']) {
                        if ($net_groups.Keys -contains $dst `
                            -or $hosts.Keys -contains $dst `
                            -or $nets.Keys -contains $dst `
                            -or $network_objects_80_40_names -contains $dst) {
                        #если объект имеется в R80.40 или ранее учитывался при формировании команд API для создания объектов, то добавляем его в поле получателя
                            $api_call_to_rule.Add("destination.$i `"$dst`"")
                            $i += 1
                        } else {
                        #иначе заменяем объект плэйсхолдером
                            if ($replaceable_dst.count -eq 0) {
                                $api_call_to_rule.Add("destination.$i `"$src_dst_placeholder`"")
                                $i += 1
                            }
                            $replaceable_dst += $dst
                        }
                    }
                }
                if ($rule['dst_negate'] -eq 'not in') {
                    $api_call_to_rule.Add("destination-negate true")
                }
                if ($rule['through'].count -gt 0 `
                    -and -not($rule['through'] -contains 'Any')) {
                #формируем vpn (пропускаем если 'Any', т.к. это эначние делается API по умолчанию)
                    $i = 1
                    foreach ($vpn in $rule['through']) {
                        if ($vpn_name[$vpn] -ne $null) {
                        #добавляем vpn если он указан в конфиге
                            $api_call_to_rule.Add("vpn.$i `"$vpn`"")
                            $i += 1
                        }
                    }
                }
                $replaceable_services = @()
                if ($rule['services'].count -gt 0 `
                    -and -not($rule['services'] -contains 'Any')) {
                #формируем сервисы (пропускаем если 'Any', т.к. это эначние делается API по умолчанию)
                    $i = 1
                    foreach ($service in $rule['services']) {
                        if ($service_groups.Keys -contains $service `
                            -or $tcp_services.Keys -contains $service `
                            -or $udp_services.Keys -contains $service `
                            -or $services_80_40_names -contains $service) {
                        #если сервис имеется в R80.40 или ранее учитывался при формировании команд API для создания сервисов, то добавляем его в поле сервисов
                            $api_call_to_rule.Add("service.$i `"$service`"")
                            $i += 1
                        } else {
                        #иначе заменяем сервис плэйсхолдером
                            if ($replaceable_services.count -eq 0) {
                                $api_call_to_rule.Add("service.$i `"$service_placeholder`"")
                                $i += 1
                            }
                            $replaceable_services += $service
                        }
                    }
                }
                if ($rule['services_negate'] -eq 'not in') {
                    $api_call_to_rule.Add("service-negate true")
                }
                if ($rule['action'].length -gt 0) {
                    $rule_action = $rule['action']
                    $api_call_to_rule.Add("action `"$rule_action`"")
                }
                if ($rule['track'].length -gt 0 `
                    -and $rule['track'] -ne 'None') {
                    $rule_track = $rule['track']
                    if ($rule_track -eq 'Alert') {
                        $api_call_to_rule.Add("track.type `"log`" track.alert `"Alert`"")
                    } else {
                        $api_call_to_rule.Add("track.type `"$rule_track`"")
                    }
                }
                if ($rule['install'].count -gt 0 `
                    -and -not($rule['install'] -contains 'Any')) {
                #формируем межсетевые экраны (пропускаем если 'Any', т.к. API делает по умолчанию значение 'Policy Targets')
                    $i = 1
                    foreach ($firewall in $rule['install']) {
                        if ($firewall_name[$firewall] -ne $null) {
                        #добавляем межсетевой экран если он указан в конфиге
                            $fw_new_name = $firewall_name[$firewall]
                            $api_call_to_rule.Add("install-on.$i `"$fw_new_name`"")
                            $i += 1
                        }
                    }
                }
                if ($date_check -ne $null `
                    -and $date_check['result'] -eq 'unexpired') {
                    $date_name = $date_check['date_name']
                    if (-not ($time_objects_80_40_names -contains $date_name)) {
                        $date_iso_8601 = $date_check['date_value_string'] + "T12:00"
                        $api_call_to_create_access_rules.Add("add time name `"$date_name`" start-now true end.iso-8601 `"$date_iso_8601`" end-never false recurrence.pattern `"Daily`"")
                        $time_objects_80_40_names += $date_name
                    }
                    $api_call_to_rule.Add("time `"$date_name`"")
                }
                
                $api_call_to_comment = ""
                if ($rule['comments'].length -gt 0) {
                    $rule_comments = $rule['comments']
                    $api_call_to_comment = "set access-rule layer `"$r80_40_layer_name`" rule-number $current_rule_number comments `"$rule_comments`""
                }
                
                $placeholders_text = ""
                if ($replaceable_src -or $replaceable_dst -or $replaceable_services) {
                    $placeholders_text = "$r77_30_rule_number -> $r80_40_rule_number placeholders`r`n"
                    $placeholders_text += if ($replaceable_src) {"`tsource ${src_dst_placeholder}: $($replaceable_src -join ', ')`r`n"} else {$null}
                    $placeholders_text += if ($replaceable_dst) {"`tdestination ${src_dst_placeholder}: $($replaceable_dst -join ', ')`r`n"} else {$null}
                    $placeholders_text += if ($replaceable_services) {"`tservices ${service_placeholder}: $($replaceable_services -join ', ')`r`n"} else {$null}
                }
                
                $api_call_to_rule_str = $api_call_to_rule -join " "
                if ($api_call_to_rule_str.length -le 2048) {
                    $api_call_to_create_access_rules.Add($api_call_to_rule_str)
                    $rule_map.Add("$r77_30_rule_number -> $r80_40_rule_number")
                    if ($api_call_to_comment.length -gt 0 `
                        -and $api_call_to_comment.length -le 2048) {
                        $api_call_to_set_comments.Add($api_call_to_comment)
                    }
                    if ($placeholders_text.length -gt 0) {
                        $placeholders_in_rules.Add($placeholders_text)
                    }
                    $current_rule_number += 1
                } else {
                    $rule_map.Add("$r77_30_rule_number -- skipped: команда API слишком длинная и не может быть выполнена")
                    $skipped_rules.Add("$r77_30_rule_number -- skipped: команда API слишком длинная и не может быть выполнена")
                }
            
            } elseif ($date_check['result'] -eq 'expired') {
                $date_name = $date_check['date_name']
                $rule_map.Add("$r77_30_rule_number -- skipped: время '$date_name' действия правила истекло")
                $skipped_rules.Add("$r77_30_rule_number -- skipped: время '$date_name' действия правила истекло")
                
            } elseif ($date_check['result'] -eq 'undefined') {
                $date_name = $date_check['date_name']
                $rule_map.Add("$r77_30_rule_number -- skipped: не удалось определить время '$date_name' действия правила")
                $skipped_rules.Add("$r77_30_rule_number -- skipped: не удалось определить время '$date_name' действия правила")
            }
        }
    }
    
    return  $api_call_to_create_access_rules, `
            $api_call_to_set_comments, `
            $placeholders_in_rules, `
            $skipped_rules, `
            $rule_map
}


function Make-API_call_to_create_udp_services {
    param(
        $udp_services,
        $color
    )
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    foreach ($service in $udp_services.Keys) {
        $api_call_line = [System.Collections.Generic.List[string]]::new()
        
        $port = $udp_services[$service]['port']
        $proto_type = $udp_services[$service]['proto_type']
        $session_timeout = $udp_services[$service]['session_timeout']
        $s_color = $udp_services[$service]['color']
        $new_color = if ($color.Keys -contains $s_color) {$color[$s_color]} else {'black'}
        
        $api_call_line.Add("add service-udp name `"$service`" port `"$port`" color `"$new_color`" ignore-warnings true")
        if ($proto_type -ne $null) {
            $api_call_line.Add("protocol `"$proto_type`"")
        }
        if ($session_timeout -gt 0) {
            $api_call_line.Add("session-timeout $session_timeout use-default-session-timeout false")
        }
        
        $result.Add($api_call_line -join ' ')
    }
    
    return $result
}


function Make-API_call_to_create_tcp_services {
    param(
        $tcp_services,
        $color
    )
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    foreach ($service in $tcp_services.Keys) {
        $api_call_line = [System.Collections.Generic.List[string]]::new()
        
        $port = $tcp_services[$service]['port']
        $proto_type = $tcp_services[$service]['proto_type']
        $session_timeout = $tcp_services[$service]['session_timeout']
        $s_color = $tcp_services[$service]['color']
        $new_color = if ($color.Keys -contains $s_color) {$color[$s_color]} else {'black'}
        
        $api_call_line.Add("add service-tcp name `"$service`" port `"$port`" color `"$new_color`" ignore-warnings true")
        if ($proto_type -ne $null) {
            $api_call_line.Add("protocol `"$proto_type`"")
        }
        if ($session_timeout -gt 0) {
            $api_call_line.Add("session-timeout $session_timeout use-default-session-timeout false")
        }
        
        $result.Add($api_call_line -join ' ')
    }
    
    return $result
}


function Make-API_call_to_create_service_groups {
    param(
        $service_groups_correct_order,
        $color
    )
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    foreach ($service_group in $service_groups_correct_order.Keys) {
        $gr_members = $service_groups_correct_order[$service_group]['members']
        $gr_color = $service_groups_correct_order[$service_group]['color']
        $new_color = if ($color.Keys -contains $gr_color) {$color[$gr_color]} else {'black'}
        $result.Add("add service-group name `"$service_group`" color `"$new_color`"")
        foreach ($member in $gr_members) {
            $result.Add("set service-group name `"$service_group`" members.add `"$member`"")
        }
    }
    
    return $result
}


function Make-API_call_to_create_nets {
    param(
        $nets,
        $color
    )
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    foreach ($net in $nets.Keys) {
        $ip_address = $nets[$net]['ip_address']
        $netmask = $nets[$net]['netmask']
        $n_color = $nets[$net]['color']
        $new_color = if ($color.Keys -contains $n_color) {$color[$n_color]} else {'black'}
        $result.Add("add network name `"$net`" subnet `"$ip_address`" subnet-mask `"$netmask`" color `"$new_color`" ignore-warnings true")
    }
    
    return $result
}


function Make-API_call_to_create_hosts {
    param(
        $hosts,
        $color
    )
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    foreach ($node in $hosts.Keys) {
        $ip_address = $hosts[$node]['ip_address']
        $h_color = $hosts[$node]['color']
        $new_color = if ($color.Keys -contains $h_color) {$color[$h_color]} else {'black'}
        $result.Add("add host name `"$node`" ip-address `"$ip_address`" color `"$new_color`" ignore-warnings true")
    }
    
    return $result
}


function Make-API_call_to_create_net_groups {
    param(
        $net_groups_correct_order,
        $color
    )
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    foreach ($net_group in $net_groups_correct_order.Keys) {
        $gr_members = $net_groups_correct_order[$net_group]['members']
        $gr_color = $net_groups_correct_order[$net_group]['color']
        $new_color = if ($color.Keys -contains $gr_color) {$color[$gr_color]} else {'black'}
        $result.Add("add group name `"$net_group`" color `"$new_color`"")
        foreach ($member in $gr_members) {
            $result.Add("set group name `"$net_group`" members.add `"$member`"")
        }
    }
    
    return $result
}


function Walk-Trail {
    param(
        $group_name,
        $groups,
        $groups_correct_order
    )
    
    $gr_items = $groups[$group_name]['members']
    $gr_color = $groups[$group_name]['color']
    
    foreach ($item in $gr_items) {
        if (($groups.Keys -contains $item) `
            -and (-not ($groups_correct_order.Keys -contains $item))) {
            Walk-Trail $item $groups $groups_correct_order
        }
    }
    $groups_correct_order[$group_name] = @{
        'members' = $gr_items;
        'color' =   $gr_color
    }
}


function Get-RuleData {
    param($rule)
    
    [int]$number = $rule.Rule_Number
    $action = $rule.action.action.Name
    $comments = $rule.comments."#cdata-section"
    $name = $rule.name."#cdata-section"
    $disabled = $rule.disabled
    $time = $rule.time.time.Name
    $track = $rule.track.track.Name
    $dst = @()
    $rule.dst.members.reference | ForEach-Object {if ($_.Name -ne $null) {$dst += $_.Name}}
    if ($dst.count -eq 0) {
        $rule.dst.compound.compound | ForEach-Object {if ($_.Name -ne $null) {$dst += $_.Name}}
    }
    $dst_negate = $rule.dst.op."#cdata-section"
    $install = @()
    $rule.install.members.reference | ForEach-Object {$install += $_.Name}
    $services = @()
    $rule.services.members.reference | ForEach-Object {$services += $_.Name}
    $services_negate = $rule.services.op."#cdata-section"
    $src = @()
    $rule.src.members.reference | ForEach-Object {if ($_.Name -ne $null) {$src += $_.Name}}
    if ($src.count -eq 0) {
        $rule.src.compound.compound | ForEach-Object {if ($_.Name -ne $null) {$src += $_.Name}}
    }
    $src_negate = $rule.src.op."#cdata-section"
    $through = @()
    $rule.through.members.reference | ForEach-Object {if ($_.Name -ne $null) {$through += $_.Name}}
    
    $result = @{
        'number' =          $number;
        'action' =          $action;
        'comments' =        $comments;
        'name' =            $name;
        'disabled' =        $disabled;
        'time' =            $time;
        'track' =           $track;
        'dst' =             $dst;
        'dst_negate' =      $dst_negate;
        'install' =         $install;
        'services' =        $services;
        'services_negate' = $services_negate;
        'src' =             $src;
        'src_negate' =      $src_negate;
        'through' =         $through
    }
    
    return $result
}


function Get-UDPserviceData {
    param($service)
    
    $port = $service.port."#cdata-section"
    $proto_type = $service.proto_type.Name
    [int]$session_timeout = $service.timeout
    $color =  $service.color."#cdata-section"
    
    $result = @{
        'port' =            $port;
        'proto_type' =      $proto_type;
        'session_timeout' = $session_timeout;
        'color' =           $color
    }
    
    return $result
}


function Get-TCPserviceData {
    param($service)
    
    $port = $service.port."#cdata-section"
    $proto_type = $service.proto_type.Name
    [int]$session_timeout = $service.timeout
    $color =  $service.color."#cdata-section"
    
    $result = @{
        'port' =            $port;
        'proto_type' =      $proto_type;
        'session_timeout' = $session_timeout;
        'color' =           $color
    }
    
    return $result
}


function Get-ServiceGroupData {
    param($service)
    
    $members = @()
    $service.members.reference | ForEach-Object {if ($_.Name -ne $null) {$members += $_.Name}}
    
    $color =  $service.color."#cdata-section"
    
    $result = @{
        'members' = $members;
        'color' =   $color
    }
    
    return $result
}


function Get-NetData {
    param($obj)
    
    $ip_address = $obj.ipaddr."#cdata-section"
    $netmask = $obj.netmask."#cdata-section"
    $color =  $obj.color."#cdata-section"
    
    $result = @{
        'ip_address' =  $ip_address;
        'netmask' =     $netmask;
        'color' =       $color
    }
    
    return $result
}


function Get-HostData {
    param($obj)
    
    $ip_address = $obj.ipaddr."#cdata-section"
    $color =  $obj.color."#cdata-section"
    
    $result = @{
        'ip_address' =  $ip_address;
        'color' =       $color
    }
    
    return $result
}


function Get-NetGroupData {
    param($obj)
    
    $members = @()
    $obj.members.reference | ForEach-Object {if ($_.Name -ne $null) {$members += $_.Name}}
    
    $color =  $obj.color."#cdata-section"
    
    $result = @{
        'members' = $members;
        'color' =   $color
    }
    
    return $result
}


function SaveTo-File {
    param(
        [System.Collections.Generic.List[string]]$lines,
        [string]$path,
        [string]$file_name_ptfx,
        [int]$start_line_num
    )
    
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType 'directory' | Out-Null
    }
    
    $lines_count = $lines.count
    $file_num = 1
    for ($i = 0; $i -lt $lines_count; $i++) {
        if (($i -eq 0) -or ($i % $start_line_num -eq 0)) {
        # с первой строки и с каждой $start_line_num (501, 301 или 100)-ой строки создаем новый файл
            $file_name_pefx = if ($file_num -lt 10) {"0${file_num}_"} else {"${file_num}_"}
            $file_name = "$path\$file_name_pefx$file_name_ptfx"
            New-Item -Path $file_name -ItemType 'file' -Force | Out-Null
            $file_num += 1
        }
        Add-Content $file_name -Value $lines[$i] -Encoding UTF8
    }
}
