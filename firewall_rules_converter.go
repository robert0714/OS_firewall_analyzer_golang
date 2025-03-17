package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/host"
)

type Rule struct {
	RuleID          string `json:"rule_id"`
	RuleName        string `json:"rule_name"`
	RuleDisplayName string `json:"rule_display_name"`
	Chain           string `json:"chain"`
	Table           string `json:"table"`
	Protocol        string `json:"protocol"`
	SrcAddress      string `json:"src_address"`
	DstAddress      string `json:"dst_address"`
	SrcPort         string `json:"src_port"`
	DstPort         string `json:"dst_port"`
	Action          string `json:"action"`
	Comments        string `json:"Description"`
}
type WinRule struct {
	RuleID          int         `json:"rule_id"`
	RuleName        string      `json:"Name"`
	RuleDisplayName string      `json:"DisplayName"`
	Description     string      `json:"Description"`
	Direction       int         `json:"Direction"`
	Action          int         `json:"Action"`
	Protocol        string      `json:"Protocol"`
	LocalPort       string      `json:"LocalPort"`
	RemotePort      string      `json:"RemotePort"`
	RemoteAddress   string      `json:"RemoteAddress"`
	LocalAddress    interface{} `json:"LocalAddress"` // 可能是 string 或 object
}

type AlgoSecData struct {
	Version        string                 `json:"version"`
	ConfigType     string                 `json:"config_type"`
	Device         map[string]interface{} `json:"device"`
	Hosts          map[string]interface{} `json:"hosts"`
	HostsGroups    map[string]interface{} `json:"hosts_groups"`
	Services       map[string]interface{} `json:"services"`
	ServicesGroups map[string]interface{} `json:"services_groups"`
	Policies       map[string]interface{} `json:"policies"`
}

// 解析 LocalAddress，確保支援不同格式
func parseLocalAddress(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return v
	case map[string]interface{}:
		if val, ok := v["value"].([]interface{}); ok {
			// 轉換成字串陣列
			var addresses []string
			for _, addr := range val {
				addresses = append(addresses, fmt.Sprintf("%v", addr))
			}
			return strings.Join(addresses, ",")
		}
	}
	return ""
}
func getWindowsFirewallRulesConsoleMock() ([]byte, error) {
	jsonFile := "get_windows_firewall_rules_mock-v2.json"
	fileContent, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("error reading mock JSON file: %v", err)
	}
	return fileContent, nil
}
func getWindowsFirewallRulesConsole() ([]byte, error) {
	psScript := "get_windows_firewall_rules.ps1"
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-File", psScript)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error getting Windows firewall rules: %v", err)
	}
	return output, nil
}
func getWindowsFirewallRules() ([]Rule, error) {
	output, err := getWindowsFirewallRulesConsole()
	//output, err := getWindowsFirewallRulesConsoleMock()
	var rules []Rule
	rules, err = convertToRuleFromWinPowerShellJson(output, err)
	if err != nil {
		return nil, fmt.Errorf("error converting rules: %v", err)
	}
	return rules, nil
}

// 解析 Action，確保支援不同格式
func parseAction(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return v
	case int:
		if v == 2 {
			return "allow"
		} else {
			return "deny"
		}
	}
	return ""
}
func convertToRuleFromWinPowerShellJson(fileContent []byte, err error) ([]Rule, error) {
	if len(fileContent) == 0 {
		return nil, fmt.Errorf("error getting Windows firewall rules: %v", err)
	}
	var winRules []WinRule
	var raw json.RawMessage
	if err := json.Unmarshal(fileContent, &raw); err != nil {
		return nil, fmt.Errorf("error parsing JSON file: %v", err)
	}
	// Check if the raw message is a single object or an array
	if raw[0] == '{' {
		// Single object
		var singleRule WinRule
		if err := json.Unmarshal(raw, &singleRule); err != nil {
			return nil, fmt.Errorf("error parsing single WinRule: %v", err)
		}
		winRules = append(winRules, singleRule)
	} else if raw[0] == '[' {
		// Array of objects
		if err := json.Unmarshal(raw, &winRules); err != nil {
			return nil, fmt.Errorf("error parsing array of WinRules: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unexpected JSON format")
	}
	var rules []Rule
	for _, winRule := range winRules {
		rule := Rule{
			RuleID:          strconv.Itoa(winRule.RuleID),
			RuleName:        winRule.RuleName,
			RuleDisplayName: winRule.RuleDisplayName,
			Chain:           "INPUT",
			Table:           "filter",
			Protocol:        winRule.Protocol,
			SrcAddress:      parseLocalAddress(winRule.RemoteAddress),
			DstAddress:      parseLocalAddress(winRule.LocalAddress),
			SrcPort:         winRule.RemotePort,
			DstPort:         winRule.LocalPort,
			Action:          parseAction(winRule.Action),
			Comments:        winRule.Description,
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func getLinuxFirewallRules() ([]Rule, error) {
	cmd := exec.Command("sudo", "iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error getting Linux firewall rules: %v", err)
	}

	return parseIptablesRules(string(output)), nil
}

func parseIptablesRules(iptablesOutput string) []Rule {
	var rules []Rule
	var currentChain string
	var ruleID int = 1

	lines := strings.Split(iptablesOutput, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "*") {
			// Table definition
			// table = line[1:]
		} else if strings.HasPrefix(line, ":") {
			// Chain definition
			parts := strings.Fields(line[1:])
			currentChain = parts[0]
		} else if strings.HasPrefix(line, "-A") {
			// Rule definition
			parts := strings.Fields(line)
			rule := Rule{
				RuleID:          fmt.Sprintf("%d", ruleID),
				RuleName:        fmt.Sprintf("%s-%d", currentChain, ruleID),
				RuleDisplayName: fmt.Sprintf("%s-%d", currentChain, ruleID),
				Chain:           currentChain,
				Protocol:        "Any",
				SrcAddress:      "Any",
				DstAddress:      "Any",
				SrcPort:         "*",
				DstPort:         "*",
				Action:          "allow",
			}

			for i := 2; i < len(parts); i++ {
				switch parts[i] {
				case "-p":
					rule.Protocol = parts[i+1]
					i++
				case "-s":
					rule.SrcAddress = parts[i+1]
					i++
				case "-d":
					rule.DstAddress = parts[i+1]
					i++
				case "--sport":
					rule.SrcPort = parts[i+1]
					i++
				case "--dport":
					rule.DstPort = parts[i+1]
					i++
				case "-j":
					rule.Action = strings.ToLower(parts[i+1])
					if rule.Action == "accept" {
						rule.Action = "allow"
					} else if rule.Action == "drop" {
						rule.Action = "deny"
					}
					i++
				}
			}

			rules = append(rules, rule)
			ruleID++
		}
	}

	return rules
}
func getSystemInfo() map[string]string {
	hostInfo, _ := host.Info()
	hostname, _ := os.Hostname()
	version := strings.Split(hostInfo.PlatformVersion, " ")[0]

	var majorVersion, minorVersion string

	if strings.Contains(version, ".") {
		parts := strings.Split(version, ".")
		majorVersion = parts[0]
		minorVersion = parts[len(parts)-1]
	} else {
		majorVersion = version
		minorVersion = "0"
	}

	systemInfo := map[string]string{
		"name":          hostname,
		"version":       version,
		"major_version": majorVersion,
		"minor_version": minorVersion,
		"hostname":      hostname,
	}

	return systemInfo
}
func contains(hosts map[string]interface{}, addr string) bool {
	for _, host := range hosts {
		if ips, ok := host.([]string); ok {
			for _, ip := range ips {
				if ip == addr {
					return true
				}
			}
		}
	}
	return false
}
func createAlgoSecJSON(rules []Rule, osType string) AlgoSecData {
	systemInfo := getSystemInfo()

	algosecData := AlgoSecData{
		Version:        "1.3",
		ConfigType:     "POLICY_BASED",
		Device:         map[string]interface{}{"@type": "Device", "name": systemInfo["name"], "major_version": systemInfo["major_version"], "version": systemInfo["version"], "hostname": systemInfo["hostname"], "minor_version": systemInfo["minor_version"]},
		Hosts:          make(map[string]interface{}),
		HostsGroups:    make(map[string]interface{}),
		Services:       make(map[string]interface{}),
		ServicesGroups: make(map[string]interface{}),
		Policies:       make(map[string]interface{}),
	}

	hosts := make(map[string]interface{})
	services := make(map[string]interface{})

	for _, rule := range rules {
		srcAddresses := []string{rule.SrcAddress}
		dstAddresses := []string{rule.DstAddress}
		protocol := rule.Protocol
		srcPort := rule.SrcPort
		dstPort := rule.DstPort
		action := rule.Action
		direction := "inbound"
		if rule.Chain == "OUTPUT" {
			direction = "outbound"
		}

		// Add hosts
		for _, addr := range srcAddresses {
			if addr != "Any" && !contains(hosts, addr) {
				hostName := "ip_" + strings.ReplaceAll(addr, "/", "_")
				hostType := "IP_ADDRESS"
				if strings.Contains(addr, "/") {
					hostType = "SUBNET"
				}

				hosts[hostName] = map[string]interface{}{
					"name": hostName,
					"ips":  []string{addr},
					"type": hostType,
				}
			}
		}

		for _, addr := range dstAddresses {
			if addr != "Any" && !contains(hosts, addr) {
				hostName := "ip_" + strings.ReplaceAll(addr, "/", "_")
				hostType := "IP_ADDRESS"
				if strings.Contains(addr, "/") {
					hostType = "SUBNET"
				}

				hosts[hostName] = map[string]interface{}{
					"name": hostName,
					"ips":  []string{addr},
					"type": hostType,
				}
			}
		}

		// Add services
		serviceName := protocol
		if srcPort != "*" {
			serviceName += fmt.Sprintf("_%s", srcPort)
		}
		if dstPort != "*" {
			serviceName += fmt.Sprintf("_to_%s", dstPort)
		}

		if _, exists := services[serviceName]; !exists {
			serviceDef := map[string]interface{}{
				"protocol": protocol,
				"src_port": srcPort,
				"dst_port": dstPort,
			}
			services[serviceName] = map[string]interface{}{
				"name":                serviceName,
				"service_definitions": []map[string]interface{}{serviceDef},
				"type":                strings.ToUpper(protocol),
			}
		}

		// Add policies
		algosecRule := map[string]interface{}{
			"rule_name":         rule.RuleID,
			"rule_display_name": rule.RuleDisplayName,
			"rule_id":           rule.RuleID,
			"line_number":       rule.RuleID,
			"rule_num":          rule.RuleID,
			"src":               formatAddresses(srcAddresses),
			"dst":               formatAddresses(dstAddresses),
			"service":           []string{serviceName},
			"action":            action,
			"direction":         direction,
			"comments":          rule.Comments,
			"log":               0,
			"enable":            "enabled",
		}

		algosecData.Policies[rule.RuleID] = algosecRule
	}

	algosecData.Hosts = hosts
	algosecData.Services = services

	return algosecData
}

func formatAddresses(addresses []string) []string {
	var formatted []string
	for _, addr := range addresses {
		if addr == "Any" {
			return []string{"Any"}
		}
		formatted = append(formatted, fmt.Sprintf("ip_%s", strings.ReplaceAll(addr, "/", "_")))
	}
	return formatted
}

func main() {
	osType := runtime.GOOS

	var rules []Rule
	var err error
	if osType == "windows" {
		fmt.Println("Detecting Windows system, getting firewall rules...")
		rules, err = getWindowsFirewallRules()

	} else if osType == "linux" {
		fmt.Println("Detecting Linux system, getting firewall rules...")
		rules, err = getLinuxFirewallRules()
	} else {
		fmt.Printf("Unsupported operating system: %s\n", osType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if len(rules) == 0 {
		fmt.Println("No firewall rules found or error occurred.")
		os.Exit(1)
	}

	algosecData := createAlgoSecJSON(rules, osType)

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting hostname:", err)
		os.Exit(1)
	}

	outputFile := fmt.Sprintf("%s_firewall_rules.algosec", hostname)
	file, err := json.MarshalIndent(algosecData, "", "  ")
	if err != nil {
		fmt.Println("Error creating JSON:", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, file, 0644); err != nil {
		fmt.Println("Error writing to file:", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully exported firewall rules to %s\n", outputFile)
}
