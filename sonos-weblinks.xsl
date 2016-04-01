<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">

  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta http-equiv="X-UA-Compatible" content="IE=edge" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <!-- Latest compiled and minified Bootstrap CSS -->
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous" />
      <!-- Optional Bootstrap theme -->
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap-theme.min.css" integrity="sha384-fLW2N01lMqjakBkx3l/M9EahuwpSfeNvV63J5ezn3uZzapT0u7EYsXMjQV+0En5r" crossorigin="anonymous" />
      <!-- Latest compiled and minified Bootstrap JavaScript -->
      <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>
      <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
      <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
      <title>Sonos Web Links</title>
    </head>
  <body>
<div class="container">
  <h2>Sonos Web Links</h2>
  <div class="table-responsive">
  <table class="table table-bordered table-striped table-hover table-condensed small">
    <thead>
      <tr>
        <th>Zone Name</th>
        <th>Model</th>
        <th>IP Address</th>
        <th>MAC Address</th>
        <th>Status</th>
        <th>Support</th>
        <th>Device Description</th>
        <th>Reboot</th>
        <th>Tools</th>
        <th>WiFi Region</th>
        <th>Adv Config</th>
        <th>WiFi Control</th>
      </tr>
    </thead>
    <tbody>
    <xsl:for-each select="//script[@id='sonos-info']">
    <xsl:sort select="elem[@key='ZoneName']"/>
    <xsl:variable name="HardwareVersion">
      <xsl:value-of select="elem[@key='HardwareVersion']"/>
    </xsl:variable>
    <xsl:variable name="IPAddress">
      <xsl:value-of select="elem[@key='IPAddress']"/>
    </xsl:variable>
    <tr>
      <td><xsl:value-of select="elem[@key='ZoneName']"/></td>
      <td><xsl:value-of select="elem[@key='modelName']"/></td>
      <td><xsl:copy-of select="$IPAddress" /></td>
      <td><xsl:value-of select="elem[@key='MACAddress']"/></td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/status</xsl:text>
          </xsl:attribute>
          /status
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/support/review</xsl:text>
          </xsl:attribute>
          /support/review
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/xml/device_description.xml</xsl:text>
          </xsl:attribute>
          /xml/device_description.xml
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/reboot</xsl:text>
          </xsl:attribute>
          /reboot
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/tools.htm</xsl:text>
          </xsl:attribute>
          /tools.htm
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/region.htm</xsl:text>
          </xsl:attribute>
          /region.htm
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/advconfig.htm</xsl:text>
          </xsl:attribute>
          /advconfig.htm
        </a>
      </td>
      <td>
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/wifictrl?wifi=on</xsl:text>
          </xsl:attribute>
          On
        </a>
        &#160;/&#160;
        <a target="_blank">
         <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/wifictrl?wifi=off</xsl:text>
          </xsl:attribute>
          Off
        </a>
        &#160;/&#160;
        <a target="_blank">
          <xsl:attribute name="href">
           <xsl:text>http://</xsl:text>
           <xsl:copy-of select="$IPAddress"/>
           <xsl:text>:1400/wifictrl?wifi=persist-off</xsl:text>
          </xsl:attribute>
          Persist-Off
        </a>
      </td>
    </tr>
    </xsl:for-each>
  </tbody>
  </table>
  </div>
  <p class="small">XML generated at <mark><xsl:value-of select="//finished/@timestr"/></mark> with command <code><xsl:value-of select="//nmaprun/@args"/></code></p>
  <h3>Sonos Web Interface References</h3>
  <ul>
    <li><a href="https://bsteiner.info/articles/hidden-sonos-interface">The Sonos Web Inferface</a></li>
    <li><a href="http://phil.lavin.me.uk/2014/08/how-to-optimize-sonos-for-best-performance/">How to optimize Sonos for best performance</a></li>
    <li><a href="https://bsteiner.info/articles/disabling-sonos-wifi">Disabling the WiFi Link on a Sonos Music Player</a></li>
    <li><a href="https://github.com/SoCo/SoCo/wiki/Information-Adresses">Sonos Information Addresses</a></li>
  </ul>
  </div>
  </body>
  </html>
</xsl:template>

</xsl:stylesheet> 