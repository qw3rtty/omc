// Package helpers provides handy helper functions to make the life easier.
package helpers

import (
    "fmt"
    "strings"
    "io/ioutil"
    "os"
)


// Opens the file of the given path and performs checks for access and validity.
// filePtr: String pointer which holds the path to the file
// Returns: Full content of the file or empty string if could not open file
func GetContentFromFileWithChecks(filePtr* string) string{
    var fileContent string = ""

    file, err := os.Open(*filePtr)
    if err != nil {
        fmt.Println("[X] Error opening payload file...")
        return fileContent
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        fmt.Println("[X] Error getting file info...")
        return fileContent
    }

    // Check if it is a regular file and readable
    if !fileInfo.Mode().IsRegular() {
        fmt.Println("[X] File is not readable...")
        return fileContent
    }

    // Read content of file
    content, err := ioutil.ReadAll(file)
    if err != nil {
        fmt.Println("[X] Error getting file content...")
        return fileContent
    }

    fileContent = string(content)
    fileContent = strings.TrimSpace(fileContent)

    return fileContent
}
