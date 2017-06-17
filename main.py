import os
import httplib2
import logging
import qrcode
import flask
import configuration

from flask import Flask
from flask import render_template
from flask import request
from oauth2client import client
from apiclient import discovery
from googleapiclient.http import MediaFileUpload

app = Flask(__name__)
app.config.from_object('configuration')

QR_IMAGE_DIR = "qr-images"
IMAGE_EXTENSION = "png"
DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive'


def sanitize_email(e):
    e = e.replace('\r', '')
    e = e.replace("@", "-at-")
    return e    


def email_to_filename(e):
    e = sanitize_email(e)
    return e + "." + IMAGE_EXTENSION


def get_credential():
    if 'credentials' not in flask.session:
        return None
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        return None
    return credentials


def upload_to_Drive(fileDict):
    credentials = get_credential()
    # TODO: check when credentials is None
    http = credentials.authorize(httplib2.Http())
    drive_service = discovery.build('drive', 'v3', http=http)
    links = {}
    for email, file_path in fileDict.iteritems:
        file_metadata = { 'name': file_path }
        media = MediaFileUpload(file_path, mimetype='image/png')
        file = drive_service.files().create(body=file_metadata,
                                            media_body=media,
                                            fields='webViewLink').execute()
        links[email] = file.get('webViewLink')
    return links


@app.route('/')
def index():
    credentials = get_credential()
    if credentials is None:
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
        return render_template('index.html')


@app.route('/oauth2callback')
def oauth2callback():
    flow = client.flow_from_clientsecrets(
        'client_secrets.json',
        scope=DRIVE_SCOPE,
        redirect_uri=flask.url_for('oauth2callback', _external=True))
    flow.params['access_type'] = 'offline'           # offline access
    flow.params['include_granted_scopes'] = 'true'   # incremental auth
    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        return flask.redirect(flask.url_for('index'))


@app.route('/generate', methods=['POST'])
def generate():
    emailsStr = request.form['emails']
    # Split by '\n' and remove 'r'
    emails = emailsStr.split("\n")
    logging.info("Received %d emails. Generating QR codes..." % (len(emails)))
    if not os.path.isdir(QR_IMAGE_DIR):
        os.makedirs(QR_IMAGE_DIR)
        logging.info("Created directory %s" % (QR_IMAGE_DIR))

    for e in emails:
        imgQR = qrcode.make(e)
        filename = os.path.join(QR_IMAGE_DIR, email_to_filename(e))
        try:
            imgQR.save(filename)
            logging.info("Generated QR code for [%s] to: %s" % (e, filename))
        except IOError:
            logging.warning("Cannot create ")

    return 'generated!'


@app.errorhandler(500)
def server_error(e):
    logging.exception('An error occurred during a request.')
    return """
    An internal error occurred: <pre>{}</pre>
    See logs for full stacktrace.
    """.format(e), 500


if __name__ == '__main__':
    # This is used when running locally. Gunicorn is used to run the
    # application on Google App Engine. See entrypoint in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)