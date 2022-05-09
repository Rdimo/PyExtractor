from colored import fg, attr


class colors:
    ## -- static colors -- ##
    red = fg('red_1')
    orange = fg('orange_4a')
    yellow = fg('yellow')
    green = fg('green_3b')
    blue = fg('sky_blue_2')
    cyan = fg('cyan')
    turquoise = fg('turquoise_4')
    purple = fg('purple_1a')
    brown = fg('#a5682a')
    white = fg('white')
    black = fg('dark_gray')

    ## -- light colors -- ##
    lred = fg('red')
    lorange = fg('orange_4a')
    lyellow = fg('yellow')
    lgreen = fg('green')
    lblue = fg('blue')
    lpurple = fg('purple_1a')
    lbrown = fg('#a5682a')
    lblack = fg('light_gray')

    ## -- attributes -- ##
    reset = attr('reset')
    bold = attr('bold')
    underline = attr('underlined')
    dim = attr('dim')

    def custom(hex_) -> str:
        return fg(hex_)
