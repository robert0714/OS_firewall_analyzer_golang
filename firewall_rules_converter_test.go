package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLocalAddress(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{"192.168.0.1", "192.168.0.1"},
		{map[string]interface{}{"value": []interface{}{"192.168.0.1", "192.168.0.2"}}, `["192.168.0.1" "192.168.0.2"]`},
	}

	for _, test := range tests {
		result := parseLocalAddress(test.input)
		assert.Equal(t, test.expected, result)
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
