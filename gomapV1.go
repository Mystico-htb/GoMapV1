/*
TerminalJockey/MrBreadcrumbs here to wish everyone a wonderful New Year as we Y33T 2019 into the sun!
This tool was written in the spirit of learning, and partially because I have seen a lot of talk about 
offensive security tools being dangerous and some people calling for a need to limit their distribution.
As someone working in security research, the lack of free and open source tools would severely handicap
my work, UNLESS I COULD WRITE MY OWN. So this is my attempt at doing so. Picked up go a few days ago and
with a healthy(ish) dose of caffeine here we are. I plan on adding implementation for threading and possibly
a rudimentary version scan a la nmap -sV. Go has been a dream to learn so expect more goodies soon. 
may get a blog post going of what I researched to learn to write this so anyone with a bit of time and 
dedication can start writing their own tools as well!
*/


package main

import (
  "fmt"
  "strings"
  "flag"
  "net"
  "time"
  //"math"
  "strconv"
)

// gets port from -p flag
var port = flag.String("p", "80", "enter ports ie. 80,443,8000-8080")
// gets taget ip from -t flag
var target = flag.String("t", "127.0.0.1", "target ip address / url")

/* ensure proper usage by checking for number of flags, go makes this easy
 by having some default sanity checks for proper flags included */
func flagSanity() bool {
  flag.Parse()
  if flag.NFlag() != 2 {
    fmt.Println("Usage: -t <ip address> -p <port number>")
    return false
  } else {
    fmt.Println("Welcome to MrBreadcrumbs GoScanner!")
    return true
  }
}

func cleanWhiteSpace(port string) []string {
  //strips whitespace for better formatting in array
  port = strings.Replace(port, " ", "", -1)
  //splits into array for port number handling
  commaSeparated := strings.Split(port, ",")
  return commaSeparated
}

func pullRanges(commaSeparated [] string) [] int {
  //initialize testArray counter and begin loop over flag
  i := 0
  scanRange := [] int {0}
  for i < len(commaSeparated) {
    //checks for hyphen port ranges
    if strings.Contains(commaSeparated[i], "-") {
      //splits by hyphen to get high and low values
      var portEnds = strings.Split(commaSeparated[i], "-")
      val1, _ := strconv.Atoi(portEnds[0])
      val2, _ := strconv.Atoi(portEnds[1])
      //calculates difference for slice generation
      difference := val1 - val2
      // handles negative port ranges
      if difference < 0 {
        difference *= -1
      }
      //initialize portRangeArray counter begin building port range for val1 < val2
      j := 0
      if val1 < val2 {
        newNumRange := [] int{val1}
          //iterates through port ranges and builds full port scan list
          for j < (difference + 1) {
          newNumRange = append(newNumRange, 0)
          copy(newNumRange[1:], newNumRange[0:])
          newNumRange[1] = (val1 + j)
          scanRange = append(scanRange, newNumRange[1])
          j += 1
        }
        //begin building port range for val2 < val1
      } else if val2 < val1 {
        newNumRange := [] int{val2}
          //iterates through port ranges and builds full port scan list
          for j < (difference + 1) {
          newNumRange = append(newNumRange, 0)
          copy(newNumRange[1:], newNumRange[0:])
          newNumRange[1] = (val2 + j)
          scanRange = append(scanRange, newNumRange[1])
          j += 1
        }
        } else {
          j += 1
        }
        //handles single ports
      } else {
        convertToInt, _ := strconv.Atoi(commaSeparated[i])
        scanRange = append(scanRange, convertToInt)
      }
      i += 1
    }
    return scanRange
}

//basic tcp connection, returns open or closed
func testConnection(port, target string) {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, port), 500*time.Millisecond)
  if err != nil {
    fmt.Println("Host:", target, "port:", port, "closed")
    //fmt.Println(err)
  } else {
    fmt.Println("Host:", target, "port:", port, "open")
    conn.Close()
  }
}

// loops through all ports to scan
func loopPorts(target string, scanRange [] int) {
  scanCounter := 0
  fmt.Println("Scanning:", target, "...")
  for scanCounter < len(scanRange) {
    currentPort := strconv.Itoa(scanRange[scanCounter])
    testConnection(currentPort, target)
    scanCounter += 1
  }
}

func main () {
  if flagSanity() == true {
    commaSeparated := cleanWhiteSpace(*port)
    portRange := pullRanges(commaSeparated)
    loopPorts(*target, portRange)
  }
}
