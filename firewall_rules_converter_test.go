package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLocalAddress(t *testing.T) {
	// 定義測試案例
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "單一IP地址",
			input:    "192.168.0.1",
			expected: "192.168.0.1",
		},
		{
			name:     "多個IP地址",
			input:    map[string]interface{}{"value": []interface{}{"192.168.0.1", "192.168.0.2"}},
			expected: `192.168.0.1,192.168.0.2`,
		},
	}

	// 遍歷測試案例並執行測試
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := parseLocalAddress(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetWindowsFirewallRulesConsoleMock(t *testing.T) {
	rules, err := getWindowsFirewallRulesConsoleMock()
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)
}

func TestConvertToRuleFromWinPowerShellJson(t *testing.T) {
	jsonFile := "get_windows_firewall_rules_mock-v2.json"
	fileContent, err := os.ReadFile(jsonFile)
	assert.NoError(t, err)

	rules, err := convertToRuleFromWinPowerShellJson(fileContent, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)
}

func TestCreateAlgoSecJSON(t *testing.T) {
	rules := []Rule{
		{
			RuleID:          "1",
			RuleName:        "Test Rule",
			RuleDisplayName: "Test Rule Display",
			Chain:           "INPUT",
			Table:           "filter",
			Protocol:        "TCP",
			SrcAddress:      "192.168.0.1",
			DstAddress:      "192.168.0.2",
			SrcPort:         "80",
			DstPort:         "80",
			Action:          "allow",
		},
	}

	algosecData := createAlgoSecJSON(rules, "windows")
	assert.Equal(t, "1.3", algosecData.Version)
	assert.Equal(t, "POLICY_BASED", algosecData.ConfigType)
	assert.NotEmpty(t, algosecData.Device)
	assert.NotEmpty(t, algosecData.Hosts)
	assert.NotEmpty(t, algosecData.Services)
	assert.NotEmpty(t, algosecData.Policies)
}

func TestGetWindowsFirewallRules(t *testing.T) {
	rules, err := getWindowsFirewallRules()
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)
}

func TestGetLinuxFirewallRules(t *testing.T) {
	rules, err := getLinuxFirewallRules()
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)
}

func TestParseIptablesRules(t *testing.T) {
	iptablesOutput := `
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
`
	rules := parseIptablesRules(iptablesOutput)
	assert.NotEmpty(t, rules)
	assert.Equal(t, 2, len(rules))
	assert.Equal(t, "22", rules[0].DstPort)
	assert.Equal(t, "80", rules[1].DstPort)
}

func TestParseAction(t *testing.T) {
	assert.Equal(t, "allow", parseAction(2))
	assert.Equal(t, "deny", parseAction(1))
	assert.Equal(t, "allow", parseAction("allow"))
	assert.Equal(t, "deny", parseAction("deny"))
}

func TestGetSystemInfo(t *testing.T) {
	systemInfo := getSystemInfo()
	assert.NotEmpty(t, systemInfo["name"])
	assert.NotEmpty(t, systemInfo["version"])
	assert.NotEmpty(t, systemInfo["major_version"])
	assert.NotEmpty(t, systemInfo["minor_version"])
	assert.NotEmpty(t, systemInfo["hostname"])
}

func TestContains(t *testing.T) {
	hosts := map[string]interface{}{
		"host1": []string{"192.168.0.1"},
		"host2": []string{"192.168.0.2"},
	}
	assert.True(t, contains(hosts, "192.168.0.1"))
	assert.False(t, contains(hosts, "192.168.0.3"))
}

func TestFormatAddresses(t *testing.T) {
	addresses := []string{"192.168.0.1", "192.168.0.2"}
	formatted := formatAddresses(addresses)
	assert.Equal(t, []string{"ip_192.168.0.1", "ip_192.168.0.2"}, formatted)
}
