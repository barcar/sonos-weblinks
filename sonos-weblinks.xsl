<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">

  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta http-equiv="X-UA-Compatible" content="IE=edge" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
      <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
      <!-- Latest compiled and minified Bootstrap CSS -->
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous" />
      <!-- Optional Bootstrap theme -->
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap-theme.min.css" integrity="sha384-fLW2N01lMqjakBkx3l/M9EahuwpSfeNvV63J5ezn3uZzapT0u7EYsXMjQV+0En5r" crossorigin="anonymous" />
      <!-- Latest compiled and minified Bootstrap JavaScript -->
      <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>
      <!-- script to reboot all Sonos devices -->
      <script src="sonos-reboot-all.js"></script>
      <title>Sonos Web Links</title>
    </head>
  <body>
    <div class="container">
      <h2>Sonos Web Links</h2>
      <table class="table table-bordered table-striped table-hover table-condensed small">
        <thead>
          <tr>
            <th>Zone Name</th>
            <th>Model</th>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>STP</th>
            <th>Status</th>
            <th>Support Review</th>
            <th>Device Description</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <xsl:variable name="STPSecondaryNodes" select="//table[@key='STPSecondaryNodes']"/>
          <xsl:for-each select="//script[@id='sonos-info']">
            <xsl:sort select="elem[@key='ZoneName']" />
            <xsl:variable name="ZoneName" select="elem[@key='ZoneName']" />
            <xsl:variable name="IPAddress" select="elem[@key='IPAddress']" />
            <xsl:variable name="MACAddress" select="elem[@key='MACAddress']" />
            <xsl:variable name="WiFiMACAddress" select="elem[@key='WiFiMACAddress']"/>
            <xsl:variable name="STPRootBridge" select="elem[@key='STPRootBridge']" />
            <xsl:variable name="STPSecondaryNode" select="$STPSecondaryNodes/elem[@key=$WiFiMACAddress or @key=$MACAddress]" />
            <xsl:variable name="RebootOrder"> 
              <xsl:call-template name="RebootOrderTemplate">
                <xsl:with-param name="root" select="$STPRootBridge" />
                <xsl:with-param name="secondary" select="$STPSecondaryNode" />
              </xsl:call-template>
            </xsl:variable> 
            <tr>
              <td><xsl:copy-of select="$ZoneName"/></td>
              <td><xsl:value-of select="elem[@key='modelName']"/></td>
              <td><xsl:copy-of select="$IPAddress" /></td>
              <td><xsl:copy-of select="$MACAddress"/> (Wired) <br /> <xsl:copy-of select="$WiFiMACAddress"/> (WiFi)</td>
              <td>
                <xsl:call-template name="StpDepthTemplate">
                  <xsl:with-param name="root" select="$STPRootBridge" />
                  <xsl:with-param name="secondary" select="$STPSecondaryNode" />
                </xsl:call-template>
              </td>
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
                <div class="btn-group btn-group-xs">
                  <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Action<span class="caret"></span></button> 
                  <ul class="dropdown-menu dropdown-menu-right">
                    <li class="dropdown-header">Zone: <xsl:copy-of select="$ZoneName"/></li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="class">
                          <xsl:text>SonosReboot </xsl:text>
                          <xsl:value-of select="$RebootOrder"/>
                        </xsl:attribute>
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/reboot</xsl:text>
                        </xsl:attribute>
                        Reboot
                      </a>
                    </li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/tools.htm</xsl:text>
                        </xsl:attribute>
                        Tools
                      </a>
                    </li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/region.htm</xsl:text>
                        </xsl:attribute>
                        Set WiFi Region
                      </a>
                    </li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/advconfig.htm</xsl:text>
                        </xsl:attribute>
                        Advanced Config
                      </a>
                    </li>
                    <li role="separator" class="divider"></li>
                    <li class="dropdown-header">Wi-Fi Control</li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/wifictrl?wifi=on</xsl:text>
                        </xsl:attribute>
                        On
                      </a>
                    </li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/wifictrl?wifi=off</xsl:text>
                        </xsl:attribute>
                        Off
                      </a>
                    </li>
                    <li>
                      <a target="_blank">
                        <xsl:attribute name="href">
                          <xsl:text>http://</xsl:text>
                          <xsl:copy-of select="$IPAddress"/>
                          <xsl:text>:1400/wifictrl?wifi=persist-off</xsl:text>
                        </xsl:attribute>
                        Persist-Off
                      </a>
                    </li>
                  </ul> <!-- Dropdown-Menu -->
                </div> <!-- Button-Group -->
              </td>
            </tr>
          </xsl:for-each>
        </tbody>
      </table>
      <p class="small">XML generated at <mark><xsl:value-of select="//finished/@timestr"/></mark> with command <code><xsl:value-of select="//nmaprun/@args"/></code></p>
      <h3>Sonos Web Interface References</h3>
      <ul>
        <li><a target="_blank" href="https://github.com/barcar/sonos-weblinks">Sonos-WebLinks on GitHub</a></li>
        <li><a target="_blank" href="https://bsteiner.info/articles/hidden-sonos-interface">The Sonos Web Inferface</a></li>
        <li><a target="_blank" href="http://phil.lavin.me.uk/2014/08/how-to-optimize-sonos-for-best-performance/">How to optimize Sonos for best performance</a></li>
        <li><a target="_blank" href="https://bsteiner.info/articles/disabling-sonos-wifi">Disabling the WiFi Link on a Sonos Music Player</a></li>
        <li><a target="_blank" href="https://github.com/SoCo/SoCo/wiki/Information-Adresses">Sonos Information Addresses</a></li>
      </ul>
    </div> <!-- Container -->
  </body>
  </html>
</xsl:template>

<xsl:template name="StpDepthTemplate">
  <xsl:param name="root"/>
  <xsl:param name="secondary"/>
    <xsl:choose>
      <xsl:when test="$root='Yes'">
        <xsl:text>&#8730;</xsl:text>
      </xsl:when>
      <xsl:when test="$secondary='Yes'">
        <xsl:text>2&#176;</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>3&#176;</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template name="RebootOrderTemplate">
  <xsl:param name="root"/>
  <xsl:param name="secondary"/>
    <xsl:choose>
      <xsl:when test="$root='Yes'">
        <xsl:text>SonosReboot1st </xsl:text>
      </xsl:when>
      <xsl:when test="$secondary='Yes'">
        <xsl:text>SonosReboot2nd </xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>SonosReboot3rd </xsl:text>
      </xsl:otherwise>
    </xsl:choose>
</xsl:template>

</xsl:stylesheet>
