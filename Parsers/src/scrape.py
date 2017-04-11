import sys
import webbrowser
import requests
import bs4
import re
import mmap

# function to send a GET request to a specified url                                                     
def webGet(url):
    webpage = requests.get(url)             # Sets a GET request to the specified url and assigns the result to webpage
    try:
        webpage.raise_for_status()          # Check if the request was successful
    except Exception as e:
        print('There was a problem with the url {}'.format(e))  # if not, indicate the error
    return webpage                          # return what was received from that web page (if anything)

# function to print content retrieved from the specified url to a specified file
def printToFile(url, filename):             
    webpage = webGet(url)                   # Receive the returned webpage from webGet
    webFile = open(filename, 'wb')          # open the given file in write and binary mode

    for chunk in webpage.iter_content(10000):       # iterate through the 10000 bytes of content read into memory in chunks
        webFile.write(chunk)                # write the the data from the webpage in chunks to the file
# Opens a file containing raw html and formats it, then prints it out to another file
def formattedHTML(filename, formattedFilename): 
    file = open(filename, 'r+')             # open the designated file for read and write, with the fp at the beginning of the file
    data = mmap.mmap(file.fileno(), 0)      # create a memory mapped file object from the file, with its file number and with 0 indicating the whole file
    html = bs4.BeautifulSoup(data, 'html.parser')   # Mkae a soup object (parse tree) by parsing out the html using Python's html parser
    formatted = html.prettify('utf-8')              # Format the soup contents into a unicode string
    formattedFile = open(formattedFilename, "wb")   # Open the formatted/pretty file for writing in binary
    formattedFile.write(formatted)                  # Write the formatted html
    formattedFile.close()

# Parses select html contents using Regular Expression
def parseHTML(filename, searchWord, numWordsBefore, numWordsAfter):
    print('***Searching in {} for the keyword {}***'.format(filename, searchWord))  # Indicate what the function is searching for in what file
    file = open(filename, 'r+')             
    data = mmap.mmap(file.fileno(), 0)      # Make a memory mapped file object of the file
    regexString = "(\\S+\\s+)"              # Initial regex string which will be a series of characters followed by a space 
    regexString = regexString + "{" + str(numWordsBefore) + "}"             # convert the number of words to a string so it can be added to the regexString
    regexString = regexString + "\\b" + searchWord + "\\b" + "(\\S+\\s+)"   # Look for the searchword where it is the middle of the matches
    regexString = regexString + "{" + str(numWordsAfter) + "}"

    for match in re.finditer(regexString, data.read().decode('utf-8')):     # for every match found using the regexString
        print('Start:{}, End: {}\n\n{}'.format(match.start(), match.end(), match.group()))  # Print out the start and ending position and the matching text
    file.close()

# Prints out just the text portion of the file
def justText(filename):
    file = open(filename, 'r+')             # Open the file in read + write mode
    data = mmap.mmap(file.fileno(), 0)      # Make a memory mapped file object of the entire file
    html = bs4.BeautifulSoup(data, 'html.parser')   # Format the soup in a readable format
    text = html.get_text()                  # Grab only the text portions of the soup
    print(text)

# Prints out links found in a given file
def justLinks(filename):
    file = open(filename, 'r+')     
    data = mmap.mmap(file.fileno(), 0)
    html = bs4.BeautifulSoup(data, 'html.parser')
    links = html.findAll("a",href=True)     # Find all instances of a and href, where href indicates a link
    for link in links:                      # for every link found
        if link['href'].startswith('http'): # Print out the link if it starts with http
            print(link)

if __name__ == '__main__':  # to test whether the script is being run on its own, meaning the Python interpreter has assigned main to its name

    parseHTML('wptest.html', 'wp-content', 4,4)


else:
    print("imported rather than run directly")  # or if it was imported, don't run anything..
