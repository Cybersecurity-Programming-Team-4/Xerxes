import sys
import webbrowser
import requests
import bs4
import os
import re
import mmap


# function to send a GET request to a specified url                                                     
def web_get(url):
    webpage = requests.get(url)             # Sets a GET request to the specified url and assigns the result to webpage
    try:
        webpage.raise_for_status()          # Check if the request was successful
    except Exception as e:
        print('There was a problem with the url {}'.format(e))  # if not, indicate the error
    return webpage                          # return what was received from that web page (if anything)

# function to print content retrieved from the specified url to a specified file
def printToFile(url, filename):
    webpage = web_get(url)                          # Receive the returned webpage from webGet
    webFile = open(filename, 'wb')                  # open the given file in write and binary mode

    for chunk in webpage.iter_content(10000):       # iterate through the 10000 bytes of content read into memory in chunks
        webFile.write(chunk)                        # write the the data from the webpage in chunks to the file
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
def find_WordPress_Indicators(filename, searchWord):
    #print('***Searching in {} for the keyword {}***'.format(filename, searchWord))  # Indicate what the function is searching for in what file
    file = open(filename, 'r+')
    connect = True
    found = False
    site_name = "http://oregonstate.edu/"
    try:
        web_page = web_get(site_name)
    except:
        print("can't connect")
        connect = False
    if connect:
        #print(web_page.content)
        if web_page.content.find(b'wp-content') != -1:
            print("Found wp-content")
        else:
            #soup = bs4.BeautifulSoup("<meta name=\"generator\" content=\"WordPress 4.8-alpha-40416\" />", 'html.parser')
            soup = bs4.BeautifulSoup(web_page.content, 'html.parser')
            #print(soup.prettify('utf-8'))
            #generator_tag = soup.find("meta", "generator")
            #print(generator_tag)
            for meta_tag in soup('meta'):
                print(meta_tag)
                try:
                    if meta_tag["name"] == 'generator':
                        print("found tag")
                        print(meta_tag['content'])
                        if 'wordpress' in meta_tag['content'].lower():
                            print("Found wordpress tag")
                            found = True
                            break
                except:
                    print("no attr for that tag")
            if not found:
                admin_page_check = requests.get(site_name + "wp-admin")
                print(site_name + "wp-admin")
                if admin_page_check.status_code == 200:
                    print("wp-admin page found")
                    found = True
                elif admin_page_check.status_code == 404:
                    print("error: 404")
                else:
                    print("Other response")
    if not found:
        print("no wordpress indicators")
    file.close()
    os.remove(filename)

if __name__ == '__main__':  # to test whether the script is being run on its own, meaning the Python interpreter has assigned main to its name

    find_WordPress_Indicators('wptest.html', 'wp-content')


else:
    print("imported rather than run directly")  # or if it was imported, don't run anything..
