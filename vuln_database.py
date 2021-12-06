import base64
import os
import re
import ssl
import sys
import time
import subprocess
import urllib
from getpass import getpass, getuser

import selenium
from bs4 import BeautifulSoup
import feedparser
import requests
import xlsxwriter
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from urllib.parse import quote
import logging
logger = logging.getLogger()
fhandler = logging.FileHandler(filename="vulns_database.log", mode='a')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fhandler.setFormatter(formatter)
logger.addHandler(fhandler)
logger.setLevel(logging.DEBUG)
# Define proxy
proxy_domain = None ## TODO Define
proxy_port = None ## TODO Define
if proxy_domain and proxy_port:
    proxy_user = getuser()
    print(proxy_user)
    proxy_password = getpass()
    proxy = "http://" + quote(proxy_user) + ":" + quote(proxy_password) + "@" + proxy_domain + ":" + proxy_port
    os.environ['http_proxy'] = proxy
    os.environ['https_proxy'] = proxy

rss_feeds = {'Ubuntu': 'https://ubuntu.com/security/notices/rss.xml',
             'Fortinet': 'https://www.fortiguard.com/rss/ir.xml',
             'Juniper': 'https://kb.juniper.net/InfoCenter/index?page=rss&channel=SECURITY_ADVISORIES&cat=SIRT_1'
                        '&detail=content',
             'Palo Alto': 'https://security.paloaltonetworks.com/rss.xml',
             'IBM': 'https://www.ibm.com/blogs/psirt/?feed=atom',
             'Huawei': 'https://www.huawei.com/en/rss-feeds/psirt/rss',
             'Pulse Secure': 'https://kb.pulsesecure.net/pkb_RSS?q=Pulse_Security_Advisories__kav;10',
             'VMWare': 'https://www.vmware.com/security/advisories.xml',
             'Cisco': 'https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml',
             'Stormshield': 'https://advisories.stormshield.eu/feed/',
             'Microsoft': 'https://msrc-blog.microsoft.com/feed',
             'F5': 'https://api-u.f5.com/support/fedsearch/v2/rss?page=1&results=50&source=kbarticles&source=techcomm'
                   '&documentType=Security%20Advisory&lastPublishedDateStart=2021-03-02&linkBack=https://support.f5'
                   '.com/csp/new-updated-articles'}


def get_content_url(constructor, url, user="", password=""):
    """
    Get the content in the URL with user/password
    :param url:
    :param constructor: cyber constructor
    :param user: user logging
    :param password: password logging
    :return: content or False
    """
    try:
        response = requests.get(url)
        response.encoding = response.apparent_encoding
        # access the data
        if response.status_code == 200:
            content = response.text
            return content
        else:
            print("no content to parse")
            return False
    except:
        print(sys.exc_info()[0])
        logging.info('Download Impossible' + constructor)
        logging.info(sys.exc_info()[0])
        return False


def get_rss(constructor, url, workbook):
    """
    Get RSS flow
    :param workbook: workbook Excel
    :param constructor: Cyber constructor
    :param url:
    :return: None
    """
    default_fields = ["Title", "Date", "Link", "Summary", "CVE"]
    try:
        from urllib.request import HTTPSHandler
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handler = HTTPSHandler(context=context)
        try:
            feed_content = feedparser.parse(url, handlers=[handler])
        except urllib.error.URLError as e:
            print(f"Error RSS Feeds {e} for {constructor}")
            pass
        worksheet = workbook.add_worksheet(constructor)
        col = 0
        for default_field in default_fields:
            worksheet.write(0, col, default_field)
            col += 1
        row = 1
        for entry in feed_content.entries:
            col = 0
            fields = []
            try:
                # Title
                title = entry.title
            except:
                title = ''
            fields.append(title)
            try:
                # Date
                published = entry.published
            except:
                published = ''
            fields.append(published)
            try:
                # Permalink
                link = entry.link
            except:
                link = ''
            fields.append(link)
            try:
                # Short description
                summary = BeautifulSoup(entry.summary, "lxml").text.replace('\n\n', '')
            except:
                summary = ''
            fields.append(summary)
            # Search CVE
            cve = re.findall("(?P<cve>CVE-[1-3][0-9]{3}-[0-9]+)", summary)
            if not cve:
                cve = re.findall("(?P<cve>CVE-[1-3][0-9]{3}-[0-9]+)", title)
            # Write fields in Excel file
            for field in fields:
                worksheet.set_column('{0}:{0}'.format(chr(col + ord('A'))), len(str(field)) + 2)
                worksheet.write(row, col, field)
                col += 1
            worksheet.write(row, col, ','.join(cve))
            row += 1
    except:
        logging.info('Téléchargement Impossible : ' + constructor)
        pass


def get_redhat(workbook):
    """

    :param workbook:
    :return:
    """
    url = "https://access.redhat.com/security/vulnerabilities"
    row = 0
    content = get_content_url("RedHat", url)
    if not content:
        pass
    default_fields = ["Title", "Date", "Impact", "Link", "CVE"]
    worksheet = workbook.add_worksheet("Redhat")
    col = 0
    for default_field in default_fields:
        worksheet.write(0, col, default_field)
        col += 1
    row = 1
    soup = BeautifulSoup(content, 'html.parser')
    table_body = soup.findAll('table')[0].find('tbody')
    table_rows = table_body.find_all('tr')
    for table_row in table_rows:
        fields = []
        cols = table_row.find_all('td')
        # title
        title = cols[0].text.replace('\n', '')
        worksheet.set_column('{0}:{0}'.format(chr(0 + ord('A'))), len(str(title)) + 2)
        worksheet.write(row, 0, title)
        # Date
        date = cols[3].text.replace('\n', '')
        worksheet.set_column('{0}:{0}'.format(chr(1 + ord('A'))), len(str(date)) + 2)
        worksheet.write(row, 1, date)
        # Severity
        impact = cols[1].text.replace('\n', '')
        worksheet.set_column('{0}:{0}'.format(chr(2 + ord('A'))), len(str(impact)) + 2)
        worksheet.write(row, 2, impact)
        # Link
        link = url.rsplit('/', 2)[0] + cols[0].find_all(href=True)[0]['href']
        worksheet.set_column('{0}:{0}'.format(chr(3 + ord('A'))), len(str(link)) + 2)
        worksheet.write(row, 3, link)
        row += 1
        # CVE
        cve = re.findall("(?P<cve>CVE-[1-3][0-9]{3}-[0-9]+)", title)
        worksheet.set_column('{0}:{0}'.format(chr(2 + ord('A'))), len(str(cve)) + 2)
        worksheet.write(row, 4, ','.join(cve))


def get_debian(workbook):
    """
    Get the content of the Debian vuln website
    :return: content
    """
    url = 'https://www.debian.org/security/dsa-long.fr.rdf'
    content = get_content_url("Debian", url)
    if not content:
        pass
    worksheet = workbook.add_worksheet("Debian")
    col = 0
    default_fields = ["Title", "Date", "Description", "Link"]
    for default_field in default_fields:
        worksheet.write(0, col, default_field)
        col += 1
    row = 1
    soup = BeautifulSoup(content, 'html.parser')
    items = soup.find_all('item')
    for item in items:
        # title
        title = item.find('title').text
        worksheet.set_column('{0}:{0}'.format(chr(0 + ord('A'))), len(str(title)) + 2)
        worksheet.write(row, 0, title)
        # Date
        date = item.find('dc:date').text
        worksheet.set_column('{0}:{0}'.format(chr(1 + ord('A'))), len(str(date)) + 2)
        worksheet.write(row, 1, date)
        # Description
        description = BeautifulSoup(item.find('description').text, "lxml").text
        worksheet.set_column('{0}:{0}'.format(chr(2 + ord('A'))), len(str(description)) + 2)
        worksheet.write(row, 2, description)
        # Link
        try:
            link = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                              item.text)[0]
        except:
            link = ''
        worksheet.set_column('{0}:{0}'.format(chr(3 + ord('A'))), len(str(link)) + 2)
        worksheet.write(row, 3, link)
        row += 1


def get_mcafee(workbook):
    """

    :param workbook:
    :return:
    """
    url = 'https://www.mcafee.com/enterprise/fr-fr/threat-center/product-security-bulletins.html'
    try:
        driver = webdriver.Ie(os.getcwd() + '\headless_ie_selenium.exe')
        driver.get(url)
        time.sleep(2)
        content = driver.page_source.encode('utf8').decode('ascii', 'ignore')
        driver.quit()
    except selenium.common.exceptions.WebDriverException as e:
        print("IE : Protected Mode settings are not the same for all zones")
        return False
    else:
        print("Ouverture IE impossible pour McAfee")
        return False
    worksheet = workbook.add_worksheet("McAfee")
    col = 0
    default_fields = ["Title", "Date", "Link", "CVE"]
    for default_field in default_fields:
        worksheet.write(0, col, default_field)
        col += 1
    row = 1
    soup = BeautifulSoup(content, 'html.parser')
    table_body = soup.find_all('table', {"id": "dynamictable"})[0].find_all('tbody')[0].find_all('tr')
    for line in table_body:
        # Description
        title = line.find_all('td')[1].text
        worksheet.set_column('{0}:{0}'.format(chr(0 + ord('A'))), len(str(title)) + 2)
        worksheet.write(row, 0, title)
        # date
        date = line.find_all('td')[2].text
        worksheet.set_column('{0}:{0}'.format(chr(1 + ord('A'))), len(str(date)) + 2)
        worksheet.write(row, 1, date)
        # Link du bulletin
        link = line.findAll('td')[0].find('a').get('href')
        worksheet.set_column('{0}:{0}'.format(chr(2 + ord('A'))), len(str(link)) + 2)
        worksheet.write(row, 2, link)
        # CVEs
        cve = re.findall("(?P<cve>CVE-[1-3][0-9]{3}-[0-9]+)", title)
        worksheet.set_column('{0}:{0}'.format(chr(2 + ord('A'))), len(str(cve)) + 2)
        worksheet.write(row, 3, ','.join(cve))
        row += 1
    return True


def get_microsoft(workbook):
    """

    :param workbook:
    :return:
    """
    url = 'https://msrc.microsoft.com/update-guide/vulnerability'

    balise = 'vulnerability-list-root'


def main():
    # File stored on the current folder
    file_excel = os.path.join(os.getcwd(), 'vulns_database.xlsx')
    # creation fichier excel
    workbook = xlsxwriter.Workbook(file_excel)
    get_mcafee(workbook)
    get_redhat(workbook)
    get_debian(workbook)
    # Get RSS flow
    for constructor, feed in rss_feeds.items():
        get_rss(constructor, feed, workbook)

    # Close Excel file
    try:
        workbook.close()
        os.startfile(file_excel)
    except xlsxwriter.exceptions.FileCreateError as e:
        logging.info("Can't create the Excel file", e)
        exit(0)
    else:
        print("Can't open the Excel file")


if __name__ == '__main__':
    main()
