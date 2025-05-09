// Package obfuscator provides utilities to obfuscate your payloads.
package ipv4 

import (
    "fmt"
    "strings"
    "strconv"
)

// Add necessary padding to the payload, so we can create a valid 
// IPv4 representation of the given payload.
// payload: String which holds the payload
// Returns correct padded payload.
func addIPv4Padding(payload string) string {
    var padded string
    var paddingChar string = " "

    // Check if padding is needed, if not return actual payload
    if (len(payload) % 4) == 0 {
        return payload
    }

    // Calculate missing length
    // Payload have to be multiple of 4, modulo operator gives us the
    // missing number to be the multiple of 4
    missingLength := 4 - (len(payload) % 4)
    padded = payload + strings.Repeat(paddingChar, missingLength) 

    return padded
}

// Generates an valid IP address from 4 rune's (characters).
// A: Rune for first IP block
// B: Rune for second IP block
// C: Rune for third IP block
// D: Rune for fourth IP block
// Returns the full IP address as string.
func GenerateIPv4(A rune, B rune, C rune, D rune) string {
    var ip string
    ip = fmt.Sprintf("%d.%d.%d.%d", int(A), int(B), int(C), int(D))

    return ip
}

// Restore given IPv4 address to its string representation.
// ip: IPv4 address which will be restored to its actual representation
// Returns the string from the IPv4 address.
func RestoreFromIPv4(ip string) string {
    var snippet string
    var splittedIP []string
    var splittedNumbers []int

    // Split and convert IP from string to number array
    splittedIP = strings.Split(ip, ".")
    for _, num := range(splittedIP) {
        number, _ := strconv.Atoi(num)
        splittedNumbers = append(splittedNumbers, number) 
    }

    // Convert numbers to unicode
    for _, num := range(splittedNumbers) {
        snippet = snippet + string(num)
    }

    return snippet
}

// Generates an IPv4 string array which represents the payload.
// payload: String which holds the payload
// Returns an string array which contains a bunch of IP addresses.
func ObfuscateToIPv4(payload string) []string{
    var ipList []string
    var ip string

    // Check if we have something to obfuscate
    if len(payload) == 0 {
        return ipList
    }

    // Check if payload is a multiple of 4, if not add padding
    if (len(payload) % 4) != 0 {
        payload = addIPv4Padding(payload) 
    }

    // Lets generate the IPv4 list
    for i, _ := range(payload) {
        // Make sure we have a range of 4 characters 
        if (i % 4) == 0 {
            ip = GenerateIPv4(rune(payload[i]), rune(payload[i+1]), 
            rune(payload[i+2]), rune(payload[i+3]))
            ipList = append(ipList, ip)
        }
    }

    return ipList
}


// Restores the actual payload.
// ipList: Array of strings with IPv4 addresses which represents the payload
// Returns the actual payload as string.
func DeobfuscateFromIPv4(ipList []string) string {
    var payload string

    // No entries in list, nothing to do
    if len(ipList) == 0 {
        return payload
    }

    for _, ip := range(ipList) {
        snippet := RestoreFromIPv4(ip)
        payload = payload + snippet
    }

    return payload
}
