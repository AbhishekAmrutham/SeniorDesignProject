import csv
import re
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

#function to read input nessus/xml file and store it into our data structure
def parseXML(xmlfile):
    # create element tree object
    tree = ET.parse(xmlfile)

    # get root element
    root = tree.getroot()

    # create empty list for news items
    ipsWithVulnerabilities = []

    # iterate news items
    for report in root.iter("Report"):
        for IP in report.iter("ReportHost"):
            #get each IP
            vulnerabilities = [IP.attrib["name"]]
            for vulnerability in IP.iter("cvss_vector"):
                #get each vulnerability vector
                vulnerabilityVector = parseBaseVector(vulnerability.text) #parse the vector
                getCVSSValues(vulnerabilityVector); #get CVSS values
                getPosture(vulnerabilityVector); #get posture of vector
                vulnerabilities.append(vulnerabilityVector) #add the vectors

            ipsWithVulnerabilities.append(vulnerabilities)

    ipsWithVulnerabilities = scaleExploitability(ipsWithVulnerabilities)
    ipsWithVulnerabilities = generateStatement(ipsWithVulnerabilities)
    ipsWithVulnerabilities = calculateStats(ipsWithVulnerabilities)

    return ipsWithVulnerabilities

#function to print all the data
def writeParsedData(nessusData):
    with open('DataFullNetwork.csv', mode='w+') as writer:
        csvWriter = csv.DictWriter(writer, None)
        csvWriter.fieldnames = ["IP", "CVSS Base Vector", "Posture", "Access Vector", "Access Vector Score",  "Access Complexity", "Access Complexity Score", "Authentication", "Authentication Score", "Confidentiality Impact", "Confidentiality Impact Score", "Integrity Impact", "Integrity Impact Score", "Availability Impact", "Availability Impact Score", "Exploitability %", "Affected Metrics", "Statement"]
        headers = dict((h, h) for h in csvWriter.fieldnames)
        csvWriter.writerow(headers) #print column headers

        #print all the vulnerability info with 2 for loops
        for IP in nessusData[:-1]:
            IPdict = {"IP": IP[0]}
            csvWriter.writerow(IPdict)
            for Vulnerability in IP[1:]:
                csvWriter.writerow(Vulnerability)

    #open the csv in a different way and print the statistics
    with open('DataFullNetwork.csv', mode='a') as writer:
        csvWriter = csv.writer(writer)
        csvWriter.writerow(['']) #print blank line
        exploitabilityLikelihood = nessusData[len(nessusData)-1]
        csvWriter.writerow([("This probability of at least 1 exploit assuming 100%% attacker capability is %.1f%%." % exploitabilityLikelihood)])

def parseBaseVector(inputVector):
    base_vectors = []  # list for holding each base vector as a dictionary
    base_dictionary = {}  # dictionary for holding each base vector as a key and value pair

    # regular expressions to match base and temporal vectors
    base_vector = re.compile(r'(AV):(\D)/(AC):(\D)/(Au):(\D)/(C):(\D)/(I):(\D)/(A):(\D)')

    # Find matches for base and temporal vectors
    base_matches = base_vector.finditer(inputVector)

    match = next(base_matches)

    base_dictionary = {match.group(1): match.group(2),
                       match.group(3): match.group(4),
                       match.group(5): match.group(6),
                       match.group(7): match.group(8),
                       match.group(9): match.group(10),
                       match.group(11): match.group(12)}

    #remap the keys to new names
    base_dictionary["Access Vector"] = base_dictionary.pop("AV")
    base_dictionary["Access Complexity"] = base_dictionary.pop("AC")
    base_dictionary["Authentication"] = base_dictionary.pop("Au")
    base_dictionary["Confidentiality Impact"] = base_dictionary.pop("C")
    base_dictionary["Integrity Impact"] = base_dictionary.pop("I")
    base_dictionary["Availability Impact"] = base_dictionary.pop("A")
    base_dictionary["CVSS Base Vector"] = inputVector

    return  base_dictionary

#function to take all the base vector characters and convert them
# to their numerical equivalent score according to CVSS
def getCVSSValues(parsedVector):
    accessVectorDictionary = {"L":0.395, "A":0.646, "N":1}
    accessComplexityDictionary = {"H":0.35, "M":0.61,  "L":0.71}
    authenticationDictionary = {"M":0.45, "S":0.56, "N": 0.704}
    confidentialityImpactDictionary = {"N": 0, "P": 0.275, "C":0.66}
    integrityImpactDictionary = {"N": 0, "P": 0.275, "C":0.66}
    availabilityImpactDictionary = {"N": 0, "P": 0.275, "C":0.66}

    parsedVector["Access Vector Score"] = accessVectorDictionary[parsedVector["Access Vector"]]
    parsedVector["Access Complexity Score"] = accessComplexityDictionary[parsedVector["Access Complexity"]]
    parsedVector["Authentication Score"] = authenticationDictionary[parsedVector["Authentication"]]
    parsedVector["Confidentiality Impact Score"] = confidentialityImpactDictionary[parsedVector["Confidentiality Impact"]]
    parsedVector["Integrity Impact Score"] = integrityImpactDictionary[parsedVector["Integrity Impact"]]
    parsedVector["Availability Impact Score"] = availabilityImpactDictionary[parsedVector["Availability Impact"]]
    parsedVector["Exploitability %"] = 20 * parsedVector["Access Vector Score"] * parsedVector["Access Complexity Score"] * parsedVector["Authentication Score"];

    affectedMetrics = []
    if(parsedVector["Confidentiality Impact"] != "N"):
        affectedMetrics.append("Confidentiality")
    if (parsedVector["Integrity Impact"] != "N"):
        affectedMetrics.append("Integrity")
    if (parsedVector["Availability Impact"] != "N"):
        affectedMetrics.append("Availability")

    parsedVector["Affected Metrics"] = ",".join(affectedMetrics);

#this function scales the exploitability from 0% to 100%
def scaleExploitability(nessusData):
    minExploitability = 1.24425
    maxExploitability = 9.9968
    #scale the exploitability values
    for IP in nessusData:
        for Vulnerability in IP[1:]:
            Vulnerability["Exploitability %"] = (Vulnerability["Exploitability %"] - minExploitability) * 100 / (maxExploitability - minExploitability);
    return nessusData

#this function finds the attacker posture
def getPosture(parsedVector):
    #based on the access vector and authentication determine the posture
    if(parsedVector["Access Vector"] == 'N'):
        parsedVector["Posture"] = "Outsider"
    elif (parsedVector["Access Vector"] == 'A' and parsedVector["Authentication"] == 'N'):
        parsedVector["Posture"] = "Nearsider"
    elif (parsedVector["Access Vector"] == 'L' and parsedVector["Authentication"] == 'N'):
        parsedVector["Posture"] = "Insider"
    else:
        parsedVector["Posture"] = "Privileged Insider"

# This function counts the number of occurrences of a list element
def countElements(lst, x):
    return lst.count(x)

# This function returns a list of the unique elements of an input list
def uniqueElements(my_list):
    list_set = set(my_list)  # insert the list to the set
    unique_list = (list(list_set))  # convert the set to the list
    return unique_list

#this function calculates stats
#the stats are likelihood of being exploited
#generates the plot for number of vulnerabilites at each exploitability level
def calculateStats(nessusData):
    noExploit = 1.0 #variable to store the likelihood of no exploitation
    for IP in nessusData:
        for Vulnerability in IP[1:]:
            noExploit *= 1-(Vulnerability["Exploitability %"]/100)
    exploitabilityLikelihood = (1 - noExploit) * 100 #calculate the likelihood of being exploited
    nessusData.append(exploitabilityLikelihood) #append this statistic to our list of vulnerabilites and IPs
    return nessusData #return the modified list

#this function generates the statement that describes a vulnerability
def generateStatement(nessusData):
    for IP in nessusData:
        for Vulnerability in IP[1:]:
            Vulnerability["Statement"] = "This vulnerability can be exploited %.1f%% of the time and it causes a loss of %s." % (Vulnerability["Exploitability %"], Vulnerability["Affected Metrics"])
    return nessusData

# this function generates the plot for number of vulnerabilites at each exploitability level
def generatePlot(nessusData):
    # prepares lists to be plotted as x and y coordinates
    listExploitabilities = []  # list to store all exploitability percentages
    totalVulnerabilities = []  # list to store the number of vulnerabilities at each level

    # gets the list of each exploitability as a float rounded to 2 decimal places
    for IP in nessusData[:-1:]:
        for Vulnerability in IP[1:]:
            listExploitabilities.append(Vulnerability["Exploitability %"])
    listExploitabilities = ['%.2f' % elem for elem in listExploitabilities]  # round each element to 2 decimal places
    listExploitabilities= [float(elem) for elem in listExploitabilities]  # convert each element to floats

    # gets the list of total vulnerabilities at each exploitability level
    possibleExploitabilities = uniqueElements(listExploitabilities)  # gets each possible exploitability value
    for eValue in possibleExploitabilities:
        totalVulnerabilities.append(countElements(listExploitabilities, eValue))

    # creates bar graph
    plt.bar(possibleExploitabilities, totalVulnerabilities, label='Exploitabilities', width=2)
    plt.xlabel('Exploitability levels')
    plt.ylabel('Vulnerabilities')
    plt.xticks(possibleExploitabilities)
    plt.title('Total vulnerabilities at each exploitability level')
    plt.legend()
    plt.show()

def runProgram(fileName):
    data = parseXML(fileName)
    #data = filterData(data); //ask for filters and filter data
    writeParsedData(data)
    generatePlot(data)

runProgram("TestData.nessus")




