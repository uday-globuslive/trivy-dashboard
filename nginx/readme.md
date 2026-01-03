Steps:
1. Add DNS record: 
Add a DNS A record or CNAME for trivy.erwindmjenkins.mycompany.com pointing to your nginx server IP.
2. Copy the nginx config to your nginx server
```
# Copy to sites-available
sudo cp trivy-dashboard.conf /etc/nginx/sites-available/trivy.conf

# Enable it
sudo ln -s /etc/nginx/sites-available/trivy.conf /etc/nginx/sites-enabled/
```
3. Get SSL certificate (if not using wildcard)
```
sudo certbot --nginx -d trivy.hostname.mycompany.com
```
4. Test and reload nginx
```
sudo nginx -t && sudo nginx -s reload
```
5. Access at:
https://trivy.hostname.mycompany.com

No Flask code changes needed - everything