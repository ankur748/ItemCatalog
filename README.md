This project deals with setting up of a category/items relationship with proper authentication and authorization of users.

- Users can do all respective CRUD operations but within the authorization of what they are actually owners of.
- Users can login to the application using third party login
- JSON data of the website is available from web endpoints to be consumed as an API
- Forms and other means are provided for effecient use of CRUD methods.

To start with the project, we need to first install Vagrant and VirtualBox

After installation, follow the below mentioned steps

1) Clone the repository with vagrant config by issuing the command

git clone https://github.com/udacity/fullstack-nanodegree-vm

2) move to the respective repository on your machine and change directory to vagrant

cd <local_repository_path>/vagrant

3) Start the vagrant instance and then ssh into the instance

vagrant up

vagrant ssh

4) Change directory in new VM to the Item Catalog application directory by issuing the command

cd /vagrant/<project_name>

5) Create a new database to work on this project by issuing the command 

python database_setup.py

You can change the database name if required and the type from sqllite to any other depending upon your convenience.

6) You can then start the flask application server by issuing the command 

python flask_server.py

It will then start the server on http://localhost:5000 which can be accessed from your local browser.

You can change the port depending upon your convenience in flask_server.py file

This application uses third party authentication to allow signing into your application to do CRUD operations. The authenticators used for this application are Google Plus and Facebook.

Please find below the steps to create projects on both the authenticators and integrate them with this flask application.

Google Plus Login

1) Login to https://console.developers.google.com
2) Create a project with appropriate name like "Item Catalog"
3) Go to credentials tab and create OAuth Credentials. It would generate appropriate client id and secret
4) Configure the application as web application and give the correct Javascript origins and redirect URL like
http://localhost:5000
5) Download the JSON file using "Download JSON" option available on console
6) Replace the contents of "google_client_secrets.json" file with the contents of downloaded json.

Google Plus Login should now be ready to use

Facebook Login

1) Login to https://developers.facebook.com/apps
2) Create a new web application there and facebook will provide app_id and app_secret
3) Replace the contents of fb_client_secrets.json file with credentials received in step 2
4) Configure the application as web application
5) Add Facebook Login product to the application and give the correct Javascript origins and redirect URL like http://localhost:5000 in the product.

Facebook Login should now be ready to use