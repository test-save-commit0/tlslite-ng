import os
if os.name != 'java':
    from datetime import datetime, timedelta
else:
    import java
    import jarray
