CREATE DATABASE  IF NOT EXISTS `Xerxes_Memory` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `Xerxes_Memory`;
-- MySQL dump 
--

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN;
SET @@SESSION.SQL_LOG_BIN= 0;

--
-- GTID state at the beginning of the backup 
--

SET @@GLOBAL.GTID_PURGED='baf129c2-2710-11e7-afb7-42010a80044a:1-2607';

--
-- Table structure for table `CMS_VULNERABILITIES`
--

DROP TABLE IF EXISTS `CMS_VULNERABILITIES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CMS_VULNERABILITIES` (
  `EXTENSION_NAME` varchar(80) CHARACTER SET latin1 NOT NULL,
  `EXTENSION_TYPE` varchar(15) NOT NULL,
  `CMS_TYPE` varchar(16) NOT NULL,
  `MIN_VERSION` varchar(16) DEFAULT 'n/a',
  `MAX_VERSION` varchar(16) DEFAULT 'n/a',
  `ATTACK_DESCRIPTION` varchar(200) NOT NULL,
  PRIMARY KEY (`EXTENSION_NAME`,`EXTENSION_TYPE`,`CMS_TYPE`,`ATTACK_DESCRIPTION`),
  UNIQUE KEY `UNIQUE_VULNERABILITY` (`EXTENSION_NAME`,`EXTENSION_TYPE`,`CMS_TYPE`,`ATTACK_DESCRIPTION`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `CVE_VULNERABILITIES`
--

DROP TABLE IF EXISTS `CVE_VULNERABILITIES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CVE_VULNERABILITIES` (
  `CVE_ID` varchar(20) NOT NULL,
  `STATUS` varchar(9) DEFAULT NULL,
  `DESCRIPTION` longtext,
  PRIMARY KEY (`CVE_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `DEVICE_INFO`
--

DROP TABLE IF EXISTS `DEVICE_INFO`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `DEVICE_INFO` (
  `IP_ADDRESS` varchar(15) NOT NULL,
  `MAC_ADDRESS` varchar(17) NOT NULL,
  `TAXONOMY` varchar(45) DEFAULT NULL,
  `VENDOR` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`IP_ADDRESS`,`MAC_ADDRESS`),
  CONSTRAINT `HAS_SITE_ENTRY` FOREIGN KEY (`IP_ADDRESS`) REFERENCES `SITE_INFO` (`IP_ADDRESS`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `GEOIP_IP_BLOCKS`
--

DROP TABLE IF EXISTS `GEOIP_IP_BLOCKS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `GEOIP_IP_BLOCKS` (
  `CIDR` varchar(18) NOT NULL,
  `NETWORK_START` int(10) unsigned NOT NULL,
  `NETWORK_END` int(10) unsigned NOT NULL,
  `GEONAME_ID` int(10) unsigned DEFAULT NULL,
  `POSTAL_CODE` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`CIDR`),
  KEY `REFERENCES_GEOIP_LOCATION_idx` (`GEONAME_ID`),
  CONSTRAINT `REFERENCES_GEOIP_LOCATION` FOREIGN KEY (`GEONAME_ID`) REFERENCES `GEOIP_LOCATION_INFO` (`GEONAME_ID`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `GEOIP_LOCATION_INFO`
--

DROP TABLE IF EXISTS `GEOIP_LOCATION_INFO`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `GEOIP_LOCATION_INFO` (
  `GEONAME_ID` int(10) unsigned NOT NULL,
  `CONTINENT` varchar(13) NOT NULL,
  `COUNTRY` varchar(80) DEFAULT NULL,
  `SUBDIVISION_1` varchar(80) DEFAULT NULL,
  `SUBDIVISION_2` varchar(80) DEFAULT NULL,
  `CITY` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`GEONAME_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SCAN_HISTORY`
--

DROP TABLE IF EXISTS `SCAN_HISTORY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SCAN_HISTORY` (
  `SCAN_ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `START_TIME` datetime NOT NULL,
  `END_TIME` datetime NOT NULL,
  PRIMARY KEY (`SCAN_ID`),
  UNIQUE KEY `Scan_ID_UNIQUE` (`SCAN_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SCAN_REQUESTS`
--

DROP TABLE IF EXISTS `SCAN_REQUESTS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SCAN_REQUESTS` (
  `REQUEST_ID` int(10) unsigned NOT NULL,
  `REQUESTER_NAME` varchar(45) NOT NULL,
  `TARGET_IP` varchar(15) NOT NULL,
  `SUBMISSION_TIME` datetime NOT NULL,
  `APPROVAL_STATUS` varchar(10) NOT NULL DEFAULT 'SUBMITTED',
  PRIMARY KEY (`REQUEST_ID`,`REQUESTER_NAME`),
  UNIQUE KEY `REQUEST_ID_UNIQUE` (`REQUEST_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SITE_INFO`
--

DROP TABLE IF EXISTS `SITE_INFO`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SITE_INFO` (
  `IP_ADDRESS` varchar(15) NOT NULL,
  `SITE_NAME` longtext,
  `IP_VERSION` varchar(4) DEFAULT NULL,
  `COUNTRY` varchar(80) DEFAULT NULL,
  `CMS_TYPE` varchar(20) DEFAULT 'Unknown',
  `VULNERABILITY_SCORE` float DEFAULT '0',
  `CHECKED_DATE` datetime NOT NULL,
  PRIMARY KEY (`IP_ADDRESS`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SITE_OPEN_SERVICES`
--

DROP TABLE IF EXISTS `SITE_OPEN_SERVICES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SITE_OPEN_SERVICES` (
  `IP_ADDRESS` varchar(15) NOT NULL,
  `PORT_NUMBER` int(11) NOT NULL,
  `SERVICE_NAME` varchar(10) NOT NULL,
  `BANNER` blob,
  PRIMARY KEY (`IP_ADDRESS`,`PORT_NUMBER`,`SERVICE_NAME`),
  CONSTRAINT `SITE_ENTRY_EXISTS_FOR_OPEN_SERVICES` FOREIGN KEY (`IP_ADDRESS`) REFERENCES `SITE_INFO` (`IP_ADDRESS`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SITE_VULNERABILITIES`
--

DROP TABLE IF EXISTS `SITE_VULNERABILITIES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SITE_VULNERABILITIES` (
  `IP_ADDRESS` varchar(15) NOT NULL,
  `TYPE` varchar(45) NOT NULL,
  `DESCRIPTION` varchar(100) NOT NULL,
  PRIMARY KEY (`IP_ADDRESS`,`DESCRIPTION`,`TYPE`),
  CONSTRAINT `SITE_ENTRY_EXISTS_FOR_VULNERABILITIES` FOREIGN KEY (`IP_ADDRESS`) REFERENCES `SITE_INFO` (`IP_ADDRESS`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `USERS`
--

DROP TABLE IF EXISTS `USERS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `USERS` (
  `USERNAME` varchar(128) NOT NULL,
  `PASSWORD` varchar(64) NOT NULL,
  `SALT` varchar(45) NOT NULL,
  `LEVEL` int(11) NOT NULL DEFAULT '0',
  `API_KEY` varchar(64) DEFAULT NULL,
  `SCANS_MADE` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`USERNAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WHOIS_INFO`
--

DROP TABLE IF EXISTS `WHOIS_INFO`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WHOIS_INFO` (
  `IP_ADDRESS` varchar(15) NOT NULL,
  `ORGANIZATION` varchar(45) NOT NULL,
  PRIMARY KEY (`IP_ADDRESS`,`ORGANIZATION`),
  CONSTRAINT `SITE_ENTRY_EXISTS_FOR_WHOIS` FOREIGN KEY (`IP_ADDRESS`) REFERENCES `SITE_INFO` (`IP_ADDRESS`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
SET @@SESSION.SQL_LOG_BIN = @MYSQLDUMP_TEMP_LOG_BIN;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-04-21 22:47:15
