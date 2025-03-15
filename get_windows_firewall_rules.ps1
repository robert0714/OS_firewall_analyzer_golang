# 取得所有啟用的防火牆規則
# $rules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.DisplayName -like 'sdo*'} | Select-Object -First 10 Name, DisplayName, Description, Direction, Action,@{Name='Protocol'; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Protocol}},@{Name='LocalPort'; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},@{Name='RemotePort'; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}},@{Name='RemoteAddress'; Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}},@{Name='LocalAddress'; Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).LocalAddress}}
$rules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Select-Object -First 10 Name, DisplayName, Description, Direction, Action,@{Name='Protocol'; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Protocol}},@{Name='LocalPort'; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},@{Name='RemotePort'; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}},@{Name='RemoteAddress'; Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}},@{Name='LocalAddress'; Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).LocalAddress}}

# 添加 rule_id 屬性
$rules | ForEach-Object -Begin { $i = 1 } -Process { $_ | Add-Member -MemberType NoteProperty -Name "rule_id" -Value $i -PassThru; $i++ } | ConvertTo-Json
