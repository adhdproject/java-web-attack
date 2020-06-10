#!/bin/bash

msfpath=''

if [ ! -d "output" ]; then
  echo 'Cannot find the "output" directory.'
  echo 'Make sure you run "weaponize.py" first and only run "serve.sh" from within the same directory.'
  exit
fi

cd output

echo "Shutting down Apache..."
sudo service apache2 stop
echo "Shutting down nginx..."
sudo service nginx stop
echo "Starting python web server..."
sudo python -m SimpleHTTPServer 80 >> http.log 2>&1 &
serverPID="$!"
echo "Now starting payload listeners. Please be patient."
"$msfpath"msfconsole -r listeners.rc

# When msfconsole shuts down we also want to kill the python server
echo "Shutting down python web server..."
sudo kill "$serverPID"
echo "You will need to restart Apache."
echo "You will need to restart nginx"

cd ..
