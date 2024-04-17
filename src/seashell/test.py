import difflib, re

my_list = [
    "apple brocoli banana pinapple",
    "agile pinpoop anana"
]

token = "apple pineapple"
matches = difflib.get_close_matches(token, my_list, cutoff=0.5)
print(my_list)
print(matches)

keyword = "use 2asfasf"
a = re.match(r"^use \d+$", keyword)
print(a)