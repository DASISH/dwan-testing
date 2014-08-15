'''
Usage: python api_unittest.py -v
'''
import unittest
import requests
import cookielib
import time
from xml2json import Xml2Json
# from requests.auth import HTTPBasicAuth
from selenium import webdriver
from selenium.webdriver.support.ui import Select  # for <SELECT> HTML form

class DWANApiTests():
    ''' Class with a logic what can be used in the tests.
    '''
    server_url = ''
    user = ''
    pwd = ''
    user_id = ''
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
            self.user_id = data['principal'][1]['xml:id']
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

    ''' Place for the specific tests
    '''

    ''' Test basic functionality:
        create - retrieve - modify - retrieve - change permissions - retrieve - delete
    '''

    def test_A10_create_annotation(self):
        annotation = ('<?xml version="1.0" encoding="UTF-8"?>' +
            '<annotation xmlns="http://www.dasish.eu/ns/addit"' +
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' +
            'xmlns:xhtml="http://www.w3.org/1999/xhtml/"' +
            'xsi:schemaLocation="http://www.dasish.eu/ns/addit http://lux17.mpi.nl/schemacat/schemas/s16/files/DASISH-schema.xsd"' +
            'URI="x"' +
            'ownerRef="y">' +
            '<headline>DWAN API Unittest annotation</headline>' +
            '<lastModified>2014-07-28T12:00:00.000+02:00</lastModified>' +
            '<body>' +
            ' <xmlBody>' +
            '  <mimeType>application/xml+xhtml</mimeType>' +
            '  <xhtml:span style="background-color:rgb(0,0,153);color:rgb(255,255,255);border: thick solid rgb(0, 0, 153);">X pointer experiment tmpTarget </xhtml:span>' +
            ' </xmlBody>' +
            '</body>' +
            '<targets>' +
            ' <targetInfo ref="tmpTarget">' +
            '  <link>https://developer.mozilla.org/en-US/docs/Building_an_Extension#xpointer(start-point(string-range(//h2[@id="Create_a_Chrome_Manifest"]/text()[1],'',0))/range-to(string-range(//h2[@id="Create_a_Chrome_Manifest"]/text()[1],'',24)))</link>' +
            '  <version>1.0</version>' +
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
