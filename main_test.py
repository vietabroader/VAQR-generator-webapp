import os
import main
import unittest

class VAQRGeneratorTestCase(unittest.TestCase):

    def setUp(self):
        main.app.testing = True
        self.app = main.app.test_client()
        self.EMAILS = ['p1@test.com', 'p2@test.com']

    def test_index(self):
        r = self.app.get('/')
        assert r.status_code == 200

    def test_generate(self):
        emailsStr = '\n'.join(self.EMAILS)
        r = self.app.post('/generate', data=dict(
            emails=emailsStr
        ), follow_redirects=True)
        assert os.path.isdir(main.QR_IMAGE_DIR),\
            'Cannot find directory ' + QR_IMAGE_DIR
        
        for e in emails:
            file_path = os.path.join(main.QR_IMAGE_DIR, main.email_to_filename(e))
            assert os.path.exists(file_path),\
                'Cannot find QR code for ' + e
      

if __name__ == '__main__':
    unittest.main()

