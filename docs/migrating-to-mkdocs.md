brew install python
pip3 install mkdocs-material
mkdir techbrunch-docs
cd techbrunch-docs
mkdocs new .

Cloned Gitbook

I setup 1password with CLI

Step 3 & 4

cp -R gitbook/* techbrunch-docs/docs


To migrate:

- {% embed url=""}
- {% hint style="warning" %} {% endhint %}
- {% code title="crack.js" %}{% endcode %}
- {% tabs %} {% tab title="gadget" %} {% endtab %}