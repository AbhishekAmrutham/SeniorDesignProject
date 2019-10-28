import csv
import re
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import ipaddress
import copy
import os
import datetime
import time


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

                #create a list of vulnerabilities per ip
                vulnerabilities.append(vulnerabilityVector) #add the vectors

            #create list of ips
            ipsWithVulnerabilities.append(vulnerabilities)

    #edit each vulnerability per ip
    ipsWithVulnerabilities = scaleExploitability(ipsWithVulnerabilities)
    ipsWithVulnerabilities = generateStatement(ipsWithVulnerabilities)
    ipsWithVulnerabilities = calculateStats(ipsWithVulnerabilities)

    return ipsWithVulnerabilities


#function to print all the data
def writeParsedData(nessusData, filename):
    with open(filename, mode='w+') as writer:
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
    with open(filename, mode='a') as writer:
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

    return base_dictionary


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


# This function generates the statement that describes a vulnerability
def generateStatement(nessusData):
    for IP in nessusData:
        for Vulnerability in IP[1:]:
            Vulnerability["Statement"] = "This vulnerability can be exploited %.1f%% of the time and it causes a loss of %s." % (Vulnerability["Exploitability %"], Vulnerability["Affected Metrics"])
    return nessusData


# this function generates the plot for number of vulnerabilites at each exploitability level
def generatePlot(nessusData, filename):
    # prepares lists to be plotted as x and y coordinates
    listExploitabilities = []  # list to store all exploitability percentages
    totalVulnerabilities = []  # list to store the number of vulnerabilities at each level

    # gets the list of each exploitability as a float rounded to 2 decimal places
    for IP in nessusData[:-1]:
        for Vulnerability in IP[1:]:
            listExploitabilities.append(Vulnerability["Exploitability %"])
    listExploitabilities = ['%.2f' % elem for elem in listExploitabilities]  # round each element to 2 decimal places
    listExploitabilities= [float(elem) for elem in listExploitabilities]  # convert each element to floats

    # gets the list of total vulnerabilities at each exploitability level
    #possibleExploitabilities = uniqueElements(listExploitabilities)  # gets each possible exploitability value
    possibleExploitabilities = [0, 3.47, 8.02, 9.03, 10.56, 14.62, 14.72, 16.62, 21.67, 21.77, 22.16, 24.55, 26.30, 30.57,
                                30.90, 32.95, 36.21, 42.09, 44.48, 48.51, 49.18, 58.79, 59.57, 63.84, 76.64, 83.91, 100.0]
    exploitabilityPercentages = ["{str(x)}%" for x in possibleExploitabilities]
    possibleExploitabilities.sort()  # puts
    for eValue in possibleExploitabilities:
        totalVulnerabilities.append(countElements(listExploitabilities, eValue))  # gets vulnerability y values for graph

    maxYValue = max(totalVulnerabilities)
    yLimit = (1.1*maxYValue)
    locations = list(range(27))
    # creates bar graph
    plt.bar(locations, totalVulnerabilities, label='Exploitabilities', align='center', width=.9)
    for a, b in zip(locations, totalVulnerabilities):
        if(b<(.1*maxYValue)):
            plt.text(a, b+(maxYValue/100), str(b), rotation='vertical', horizontalalignment='center', verticalalignment='bottom')
        else:
            plt.text(a, b, str(b), rotation='vertical', horizontalalignment='center', verticalalignment='top')
    plt.ylim(top=yLimit)
    plt.xlabel('Exploitability percentages')
    plt.ylabel('Vulnerabilities')
    plt.xticks(locations, possibleExploitabilities, rotation="vertical")
    plt.title('Total vulnerabilities at each exploitability level')
    plt.savefig(filename, bbox_inches='tight')
    plt.clf()


def likeElement(a,b):
    return not set(a).isdisjoint(b)


def validateIpaddress(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError as errorCode:
        #uncomment below if you want to display the exception message.
        #print(errorCode)
        #comment below if above is uncommented.
        pass
        return False


def yesPrompt(promptString):
    while(True):
        inputString = input(promptString + " (Y/N)").upper()
        if inputString == 'Y' or inputString == 'YES':
            return 'y'
        elif inputString == 'N' or inputString == 'NO':
            return 'n'
        else:
            print("\n\nEnter in a valid option")
            continue




def filterByPosturesPrompt():
    filterPostures = list()
    custom_filter = yesPrompt("\nWould you like to filter by postures?")
    if custom_filter == 'y':
        while(True):
            filter_setting = input("\nHow would you like to filter?\n"
                                   "(Seperate Values with a comma)\n"
                                   "(Enter in all values before pressing enter)\n"
                                   "1 Privileged Insider\n"
                                   "2 Insider\n"
                                   "3 Nearsider\n"
                                   "4 Outsider\n")
            filterList = list()
            filterList = filter_setting.split(",")
            if likeElement(['1', '2', '3', '4'], filterList):
                for filter in filterList:
                    # Filter by Privileged Insider
                    if filter == '1':
                        filterPostures.append("Privileged Insider")

                    # Filter by Insider
                    elif filter == '2':
                        filterPostures.append("Insider")

                    # Filter by Nearsider
                    elif filter == '3':
                        filterPostures.append("Nearsider")

                    # Filter by Outsider
                    elif filter == '4':
                        filterPostures.append("Outsider")
                break
            else:
                print("\n\nEnter in a valid option")
                continue
    else:
        filterPostures.append("Privileged Insider")
        filterPostures.append("Insider")
        filterPostures.append("Nearsider")
        filterPostures.append("Outsider")
    return filterPostures


def filterByImpactsPrompt():
    filterImpacts = list()
    filterImpacts.append(False)
    filterImpacts.append(False)
    filterImpacts.append(False)
    custom_filter = yesPrompt("\nWould you like to filter by impacts?")
    if custom_filter == 'y':
        while(True):
            filter_setting = input("\n\n\nHow would you like to filter?\n"
                                   "(Seperate Values with a comma)\n"
                                   "(Enter in all values before pressing enter)\n"
                                   "1 Availability\n"
                                   "2 Confidentiality\n"
                                   "3 Integrity\n")

            filterList = list()
            filterList = filter_setting.split(",")
            if likeElement(['1', '2', '3'], filterList):
                for filter in filterList:
                    # return string on selected input
                    # Filter by Confidentiality
                    if filter == '1':
                        filterImpacts[0] = True

                    # Filter by Integrity
                    elif filter == '2':
                        filterImpacts[1] = True

                    # Filter by Availability
                    elif filter == '3':
                        filterImpacts[2] = True
                break
            else:
                print("\n\nEnter in a valid option")
                continue

    else:
        filterImpacts[0] = True
        filterImpacts[1] = True
        filterImpacts[2] = True
    return filterImpacts


def filterByIPsPrompt():
    filterIPs = list()
    custom_filter = yesPrompt("\nWould you like to filter by IPs?")
    if custom_filter == 'y':
        while(True):
            filter_setting = input("\nHow would you like to filter?\n"
                                   "1 Single IP\n"
                                   "2 Range of IPs\n")

            # make sure input is an accepted value


            # return string on selected input
            # Filter by Confidentiality
            if filter_setting == '1':
                while(True):
                    IP = input("Which IP do you want?")
                    if validateIpaddress(IP):
                        filterIPs.append(IP)
                        filterIPs.append(IP)
                        break
                    else:
                        print("\n\nNot a valid IP")
                        continue

            # Filter by Integrity
            elif filter_setting == '2':
                while(True):
                    IP = input("Enter in the lower range:")
                    if validateIpaddress(IP):
                        filterIPs.append(IP)
                        break
                    else:
                        print("\n\nNot a valid IP")
                        continue
                while(True):
                    IP = input("Enter in the upper range:")
                    if validateIpaddress(IP):
                        filterIPs.append(IP)
                        break
                    else:
                        print("\n\nNot a valid IP")
                        continue
            else:
                print("\n\nEnter in a valid option")
                continue
            break
    else:
        filterIPs.append("000.000.000.000")
        filterIPs.append("255.255.255.255")
    return filterIPs


def createFileName(postures, impacts, IPs):
    fileName = "P-"
    if "Privileged Insider" in postures:
        fileName += "P"
    if "Insider" in postures:
        fileName += "I"
    if "Nearsider" in postures:
        fileName += "N"
    if "Outsider" in postures:
        fileName += "O"
    fileName += "__"

    fileName += "I-"
    if (impacts[0] == True):
        fileName += "A"
    if (impacts[1] == True):
        fileName += "C"
    if (impacts[2] == True):
        fileName += "I"
    fileName += "__"

    if (IPs[0] == "000.000.000.000" and IPs[1] == "255.255.255.255"):
        fileName += ""
    else:
        fileName += "IP_"

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Mm%Ss')
    fileName += st
    return fileName


def customFilterPrompt(nessusData, path):
    filterPostures = list()
    filterImpacts = list()
    # Get info from user
    # Custom filter?
    custom_filter = yesPrompt("Would you like to create a custom filter?")

    # make sure input is an accepted value

    while (True):
        # if yes
        if custom_filter == 'y':

            while(True):

                # Type of filter to use?
                # Filter By Posture
                filterPostures = filterByPosturesPrompt()

                # Filter By Impact
                filterImpacts = filterByImpactsPrompt()

                # Filter Bt IPs
                filterIPs = filterByIPsPrompt()

                # Create Filter Data File Name
                filterFileName = createFileName(filterPostures, filterImpacts, filterIPs)

                # Need to handle files that become empty after filtering
                # Create Filter Data File
                data = copy.deepcopy(nessusData)

                # Filter New File
                filterDataByPosture(data, filterPostures)
                filterDataByImpact(data, filterImpacts)
                filterDataByIP(data, filterIPs)
                removeEmptyIPs(data)
                data = data[:-1]
                if len(data) == 0:
                    print("\n\nThe filters used removed all vulnerabilities\nTry again with different filters")
                    continue
                else:
                    calculateStats(data)
                    writeParsedData(data, path + '/' + filterFileName + '.csv')
                    generatePlot(data, path + '/' + filterFileName + '.png')
                    break

        else:
            break

        custom_filter = yesPrompt("Would you like to create an additional custom filter?")

def removeEmptyIPs(nessusData):
    for IP in nessusData[:-1]:
        if (len(IP) == 1):
            nessusData.remove(IP)

def filterDataByPosture(nessusData, postures):
    for IP in nessusData[:-1]:
        for Vulnerability in IP[1:]:
            if not(Vulnerability["Posture"] in postures):
                IP.remove(Vulnerability)


#pass in the data to be filtered and then a parameter which is an array that contains
def filterDataByIP(nessusData, startandendIP):
    start = ipaddress.IPv4Address(startandendIP[0])
    end = ipaddress.IPv4Address(startandendIP[1])
    for IP in nessusData[:-1]:
            address = ipaddress.IPv4Address(IP[0])
            if (address < start or address > end):
                nessusData.remove(IP)


def filterDataByImpact(nessusData, impact):
    for IP in nessusData[:-1]:
        for Vulnerability in IP[1:]:
            #3 variables to store if the vulnerability affects either of those 3 criterias
            #These variables will be false if we aren't filtering for those criterias
            availability = impact[0] and Vulnerability["Availability Impact"] != 'N' #if vulnerability is concerned with then availability must be affected
            confidentiality = impact[1] and Vulnerability["Confidentiality Impact"] != 'N' #if vulnerability is concerned with then confidentiality must be affected
            integrity = impact[2] and Vulnerability["Integrity Impact"] != 'N' #if vulnerability is concerned with then integrity must be affected

            #if the vulnerability is not in either of the categories we are intersted in, then remove it
            if not(availability or confidentiality or integrity):
                        IP.remove(Vulnerability)


def createScanFolder():
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%Hh%Mm%Ss')

    # create output folder
    path = os.getcwd()  + "/Output/"

    try:
        if(not os.path.isdir(path)):
            os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)

    #create path of specific folder for this output
    path = os.getcwd() + "/Output/" + st

    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)

    return path


FILENAME = input("What is the input nessus file name(specify with nessus extension)?: ")
data = parseXML(FILENAME)
path = createScanFolder();
customFilterPrompt(data, path)
writeParsedData(data, path + "/FullNetworkScan.csv")
generatePlot(data, path + '/FullNetworkScan.png')






