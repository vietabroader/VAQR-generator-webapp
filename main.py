import os
import logging
import qrcode

from flask import Flask
from flask import render_template
from flask import request

app = Flask(__name__)

QR_IMAGE_DIR = "qr-images"
IMAGE_EXTENSION = "png"

@app.route('/')
def home():
    return render_template('index.html')


def sanitize_email(e):
    e = e.replace('\r', '')
    e = e.replace("@", "-at-")
    return e    


def email_to_filename(e):
    e = sanitize_email(e)
    return e + "." + IMAGE_EXTENSION


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