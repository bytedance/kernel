MODULE_EEPROM
=============

Fetch module EEPROM data dump.
This interface is designed to allow dumps of at most 1/2 page at once. This
means only dumps of 128 (or less) bytes are allowed, without crossing half page
boundary located at offset 128. For pages other than 0 only high 128 bytes are
accessible.

Request contents:

  =======================================  ======  ==========================
  ``ETHTOOL_A_MODULE_EEPROM_HEADER``       nested  request header
  ``ETHTOOL_A_MODULE_EEPROM_OFFSET``       u32     offset within a page
  ``ETHTOOL_A_MODULE_EEPROM_LENGTH``       u32     amount of bytes to read
  ``ETHTOOL_A_MODULE_EEPROM_PAGE``         u8      page number
  ``ETHTOOL_A_MODULE_EEPROM_BANK``         u8      bank number
  ``ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS``  u8      page I2C address
  =======================================  ======  ==========================

Kernel response contents:

 +---------------------------------------------+--------+---------------------+
 | ``ETHTOOL_A_MODULE_EEPROM_HEADER``          | nested | reply header        |
 +---------------------------------------------+--------+---------------------+
 | ``ETHTOOL_A_MODULE_EEPROM_DATA``            | nested | array of bytes from |
 |                                             |        | module EEPROM       |
 +---------------------------------------------+--------+---------------------+

``ETHTOOL_A_MODULE_EEPROM_DATA`` has an attribute length equal to the amount of
bytes driver actually read.

Request translation
 ===================

  ``ETHTOOL_GMODULEINFO``             ``ETHTOOL_MSG_MODULE_EEPROM_GET``
  ``ETHTOOL_GMODULEEEPROM``           ``ETHTOOL_MSG_MODULE_EEPROM_GET``
