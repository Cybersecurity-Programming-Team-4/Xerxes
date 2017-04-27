# Xerxes: An autonomous scanner, analyzer, and data repository.

Xerxes is a cybersecurity project made for the purpose of the reconnaisance and scanning stages of the Ethical Hacking Process with a small directed focus towards WordPress sites due to their popularity. All information gathered is freely shared and methods used are non-intrusive. 

Usage of an already launched instance of Xerxes can be done by going to [Xerxes.cc](http://www.xerxes.cc)

## Xerxes' "arms" are :
[MASSCAN](https://github.com/robertdavidgraham/masscan) by Robert Graham for service enumeration.

[WPScan](https://github.com/wpscanteam/wpscan) by the WPScan Team to assess a site for WordPress elements.

Information gathered from these tools are then processed and stored within the instance housing Xerxes and can be queried by users.

Querying occurs from Xerxes' face, a sleek website acting as a front end to this project.

## Installation:
Xerxes can be used by cloning this repository for the client, and another package for the server in their respective isntances.
However, Xerxes was built for and deployed on Google's Cloud Platform, so an account will be necessary to access that platform. 
A free trial is provided and can be used for deployment.

The current iteration of Xerxes uses:
2 Compute Engine VM's
1 Storage Bucket
1 Second Generation Cloud SQL server with SSL Certificates [Reference/Guide](https://cloud.google.com/sql/docs/mysql/configure-ssl-instance)
Unforunately, these will all need to be manually configured.

Following this, the easiest way to get Xerxes onto the instances are to clone the repo and server packages:
git clone https://github.com/Cybersecurity-Programming-Team-4/Xerxes.git

Following this, run setup.py to acquire the needed libraries, the manual commands are:

$ pip3 install pymysql

$ pip3 install Naked

$ pip3 install --upgrade google-api-python-client

$ pip3 install --upgrade google-cloud

$ pip3 install cStringIO

Then sudo apt-get install ruby-full to run WPScan, which can be considered an optional component.

$ cd Scanners/src/wpscan

$ bundle install

Then start up Xerxes by running main.py and scans will begin.

## Licenses
Xerxes' is released without a license as it was built with the motivation as an educational project and for non-commercial use.
However, associated Licenses exist for 

[Masscan:](https://github.com/robertdavidgraham/masscan/blob/master/LICENSE) GNU Affero General Public License version 3 and a Copyright (c) 2013 Robert David Graham

[WPScan:](https://github.com/wpscanteam/wpscan/blob/master/LICENSE) Dual License under WPScan and Copyright 2011-2016 WPScan Team. 

## Disclaimer
Xerxes is provided "as is" and built with the principle of non-intrusiveness in mind to comply with ethical practices. 

By using Xerxes, and in the case of launching your own isntance, you agree that you are responsible for the actions you perform and the authors are in no way be liable for any damages.

Support for Xerxes is not guaranteed although the authors might extend its capabilities if time and resources permit.

