'''
Usage: python api_unittest.py -v
'''
import unittest
import requests
import cookielib
import time
import datetime
from xml2json import Xml2Json
from selenium import webdriver
from selenium.webdriver.support.ui import Select  # for <SELECT> HTML form

class DWANApiTests():
    ''' Class with a logic what can be used in the tests.
    '''
    server_url = ''
    user = ''
    pwd = ''
    prid = ''
    s = requests.Session()
    cookiejar = cookielib.LWPCookieJar()

    def loadUserInfo(self, filename):
        ''' Read username and password from external file.
            File structure must be following:
            username = myusername
            password = mypassword
            
            NB! Do not add that file into repository!
        '''
        inf = open(filename, 'r')
        self.assertIsNotNone(inf, 'Missing file "' + filename + '"')
        line = inf.readline()
        fields = line.split('=')
        if (fields[0].strip() == 'username'):
            self.user = fields[1].strip()
        line = inf.readline()
        fields = line.split('=')
        if (fields[0].strip() == 'password'):
            self.pwd = fields[1].strip()
        inf.close()

    def ask_login_state(self):
        # print 'S ', requests.utils.dict_from_cookiejar(self.cookiejar)
        r = self.s.get(self.server_url + 'api/authentication/principal', cookies=self.cookiejar)
        return r

    def do_basic_login(self):
        r = self.s.get(self.server_url + 'api/authentication/login')
        if (r.status_code == 200):
            payload = {'username': self.user, 'password': self.pwd}
            r = self.s.post(self.server_url + 'j_spring_security_check', data=payload)
        return r

    def do_shibboleth_login(self):
        driver = webdriver.Firefox()
        driver.get(self.server_url + 'api/authentication/login')
        time.sleep(2)
        driver.find_element_by_class_name('discojuice_showmore').click()  # 'Click here to show external identity providers'
        driver.find_element_by_css_selector("div#scroller > a[title='Clarin.eu website account']").click()
        driver.find_element_by_name('j_username').send_keys(self.user)
        driver.find_element_by_name('j_password').send_keys(self.pwd)
        driver.find_element_by_css_selector("input[value='Login']").click()
        cs = driver.get_cookies()
        driver.close()
        self.cookiejar = cookielib.LWPCookieJar()
        for c in cs:
            # print c
            ck = cookielib.Cookie(version=0, name=c['name'], value=c['value'], port=None, port_specified=False,
                                  domain=c['domain'], domain_specified=True, domain_initial_dot=False,
                                  path=c['path'], path_specified=True, secure=False, expires=None, discard=False,
                                  comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
            self.cookiejar.set_cookie(ck)
        # print 'B ', requests.utils.dict_from_cookiejar(self.cookiejar)
        self.s.cookies = self.cookiejar
        return self.s.get(self.server_url + 'api/authentication/principal')

    def ask_principal_data(self):
        # print 'P ', requests.utils.dict_from_cookiejar(self.cookiejar)
        r = self.s.get(self.server_url + 'api/authentication/principal', cookies=self.cookiejar)
        try:
            data = Xml2Json(r.text).result
            self.prid = data['principal'][1]['xml:id']
        except:
            pass
        return r

class DWANApiTestsBasic(unittest.TestCase, DWANApiTests):
    server_url = 'http://lux17.mpi.nl/ds/webannotator-basic/'  # for non-shibboleth users

    def setUp(self):
        ''' Read username and password from external file.
        '''
        self.loadUserInfo('basic_user.inf')

    ''' Tests for LOGIN
    '''

    def test_A00_not_login_state(self):
        '''
        API should return 401 when user is not authenticated
        '''
        r = self.ask_login_state()
        self.assertEqual(r.status_code, 401)

    def test_A01_do_basic_login(self):
        r = self.do_basic_login()
        self.assertEqual(r.status_code, 200)

    def test_A02_login_state(self):
        r = self.ask_principal_data()
        self.assertEqual(r.status_code, 200)
        print '\nPRID=' + self.prid

    ''' Place for the specific tests
    '''

    ''' Test basic functionality:
        create - retrieve - modify - retrieve - change permissions - retrieve - delete
    '''

    def test_A10_create_annotation(self):
        r = self.ask_principal_data()
        now = datetime.datetime.now().isoformat()
        annotation = ('<?xml version="1.0" encoding="UTF-8"?> ' +
            '<annotation xmlns="http://www.dasish.eu/ns/addit" ' +
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
            'xsi:schemaLocation="http://www.dasish.eu/ns/addit http://lux17.mpi.nl/ds/webannotator-basic/SCHEMA/DASISH-schema.xsd" ' +
            'xmlns:xhtml="http://www.w3.org/1999/xhtml" ' +
            'xml:id="A0000000-0000-0000-2014" ' +
            'href="/ds/webannotator-basic/api/annotations/0"> ' +
            '<ownerHref>/ds/webannotator-basic/api/principals/' + self.prid + '</ownerHref> ' +
            '<headline>DWAN API Unittest annotation</headline>' +
            '<lastModified>' + now + '</lastModified>' +
            '<body>' +
            ' <xmlBody>' +
            '  <mimeType>application/xml+xhtml</mimeType>' +
            '  <xhtml:span title="December 1989" style="background-color: rgb( 44, 254,  81);color:rgb(0,0,0);">December 1989</xhtml:span>' +
            ' </xmlBody>' +
            '</body>' +
            '<targets>' +
            ' <targetInfo href="/ds/webannotator-basic/api/targets/00000000-0000-0000-2014-072812390200">' +
            '  <link>http://en.wikipedia.org/wiki/Python_(programming_language)#xpointer(start-point(string-range(//div[@id="toc"]/following-sibling::blockquote[1]/p[1]/text()[1],'',23))/range-to(string-range(//div[@id="toc"]/following-sibling::blockquote[1]/p[1]/text()[1],'',36)))</link>' +
            '  <version>' + now + '</version>' +
            ' </targetInfo>' +
            '</targets>' +
            '<permissions public="read">' +
            # '<permission level = "write" principalRef="http://lux17.mpi.nl/ds/webannotator/api/principals/00000000-0000-0000-0000-000000000112"/>'+
            # '<permission level = "write" principalRef="http://lux17.mpi.nl/ds/webannotator/api/princiapls/00000000-0000-0000-0000-000000000111"/>'+
            '</permissions>' +
            '</annotation>')
        headers = {'Content-Type': 'application/xml'}
        r = self.s.post(self.server_url + 'api/annotations', data=annotation, headers=headers)
        self.assertEqual(r.status_code, 200)

    def test_A11_retrieve_annotation_by_owner(self):
        r = self.ask_principal_data()
        params = '?owner=' + self.prid
        r = self.s.get(self.server_url + 'api/annotations' + params, cookies=self.cookiejar)
        self.assertEqual(r.status_code, 200)
        try:
            data = Xml2Json(r.text).result
            print data
        except:
            print 'Error on Xml2Json\n'

    ''' Tests for LOGOUT
    '''

    def test_Azy_do_logout(self):
        r = self.s.get(self.server_url + 'api/authentication/logout')
        self.s.close()
        self.s.cookies = requests.cookies.RequestsCookieJar()
        self.assertEqual(r.status_code, 200)

    def test_Azz_not_login_state_after_logout(self):
        '''
        API should return 401 when user is not authenticated
        '''
        r = self.ask_login_state()
        self.assertEqual(r.status_code, 401)
        self.user_id = ''

    def tearDown(self):
        self.s.close()

class DWANApiTestsShibboleth(unittest.TestCase, DWANApiTests):
    server_url = 'http://lux17.mpi.nl/ds/webannotator/'  # for non-shibboleth users

    def setUp(self):
        ''' Read username and password from external file.
        '''
        self.loadUserInfo('shibboleth_user.inf')

    ''' Tests for LOGIN
    '''

    def test_B00_not_login_state(self):
        '''
        API should return 401 when user is not authenticated
        '''
        r = self.ask_login_state()
        self.assertEqual(r.status_code, 401)

    def test_B01_do_shibboleth_login(self):
        r = self.do_shibboleth_login()
        self.assertEqual(r.status_code, 200)

    def test_B02_login_state(self):
        r = self.ask_login_state()
        # print r.text
        self.assertEqual(r.status_code, 200)



if __name__ == '__main__':
    unittest.main()
