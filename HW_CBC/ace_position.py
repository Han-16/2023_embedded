def getPositionOfAce(num_of_cards, shuffles):
    position = 0

    for shuffle in shuffles:
        top = num_of_cards // 2
        bottom = num_of_cards // 2
        ace_is_in_top = position + 1 > num_of_cards // 2

        if ace_is_in_top:
            position = position - top
            if shuffle > 0:
                bottom -= shuffle








if __name__ == "__main__":
    # num_of_cards = int(input().strip())
    num_of_cards = 52

    # shuffles_count = int(input().strip())
    shuffles_count = 1

    # shuffles = list(map(int, input().rstrip().split()))
    shuffles = [1, 17, 12, 26, 9]

    position = getPositionOfAce(num_of_cards, shuffles)
    print(position)