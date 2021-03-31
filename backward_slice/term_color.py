TC_BLACK = "\033[1;30m"
TC_RED = "\033[1;31m"
TC_GREEN = "\033[1;32m"
TC_YELLOW = "\033[1;33m"
TC_BLUE = "\033[1;34m"
TC_MAGENTA = "\033[1;35m"
TC_CYAN = "\033[1;36m"
TC_WHITE = "\033[1;37m"
TC_BRIGHT_BLACK = "\033[1;90m"
TC_BRIGHT_RED = "\033[1;91m"
TC_BRIGHT_GREEN = "\033[1;92m"
TC_BRIGHT_YELLOW = "\033[1;93m"
TC_BRIGHT_BLUE = "\033[1;94m"
TC_BRIGHT_MAGENTA = "\033[1;95m"
TC_BRIGHT_CYAN = "\033[1;96m"
TC_BRIGHT_WHITE = "\033[1;97m"
TC_BACK_BLACK = "\033[40m"
TC_BACK_RED = "\033[41m"
TC_BACK_GREEN = "\033[42m"
TC_BACK_YELLOW = "\033[43m"
TC_BACK_BLUE = "\033[44m"
TC_BACK_MAGENTA = "\033[45m"
TC_BACK_CYAN = "\033[46m"
TC_BACK_WHITE = "\033[47m"
TC_BACK_BRIGHT_BLACK = "\033[40;1m"
TC_BACK_BRIGHT_RED = "\033[41;1m"
TC_BACK_BRIGHT_GREEN = "\033[42;1m"
TC_BACK_BRIGHT_YELLOW = "\033[43;1m"
TC_BACK_BRIGHT_BLUE = "\033[44;1m"
TC_BACK_BRIGHT_MAGENTA = "\033[45;1m"
TC_BACK_BRIGHT_CYAN = "\033[46;1m"
TC_BACK_BRIGHT_WHITE = "\033[47;1m"
TC_RESET = "\033[0m"


colors = {
	"black":"\033[1;30m",
	"red":"\033[1;31m",
	"green":"\033[1;32m",
	"yellow":"\033[1;33m",
	"blue":"\033[1;34m",
	"magenta":"\033[1;35m",
	"cyan":"\033[1;36m",
	"white":"\033[1;37m",
	"bright_black":"\033[1;90m",
	"bright_red":"\033[1;91m",
	"bright_green":"\033[1;92m",
	"bright_yellow":"\033[1;93m",
	"bright_blue":"\033[1;94m",
	"bright_magenta":"\033[1;95m",
	"bright_cyan":"\033[1;96m",
	"bright_white":"\033[1;97m",
}


def color(s, color):
	return "{}{}{}".format(color, s, TC_RESET)

class Colorer(object):

	def __init__(self, start_color=None):
		if start_color == None:
			start_color = 'red'
		self._current_color = start_color

		self._uses = {}
		for color in colors:
			self._uses[color] = 0
			

	def color(self, s, color=None):
		if color == None:
			color = self._current_color
		self._uses[color] += 1
		return color(s, colors[color])

	def select(self, color):
		self._current_color = color		
