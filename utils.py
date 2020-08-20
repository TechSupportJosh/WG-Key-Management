import calendar

# https://stackoverflow.com/questions/5067218/get-utc-timestamp-in-python-with-datetime
def dt2ts(dt):
    """Converts a datetime object to UTC timestamp

    naive datetime will be considered UTC.

    """

    return calendar.timegm(dt.utctimetuple())