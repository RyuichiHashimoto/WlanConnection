from logging import getLogger,INFO, StreamHandler,FileHandler,Formatter, DEBUG

LEVEL = DEBUG

formatter = Formatter('[%(asctime)s] [%(levelname)s]  [%(filename)s] [%(funcName)s] :  %(message)s')
logger = getLogger(__name__);

## normal handler
handler = StreamHandler();
handler.setLevel(LEVEL);
handler.setFormatter(formatter)

##
handler_file = FileHandler(filename='logger.log');
handler_file.setLevel(LEVEL)
handler_file.setFormatter(formatter)


logger.setLevel(LEVEL);
logger.addHandler(handler);
logger.addHandler(handler_file);
