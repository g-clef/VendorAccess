def fixFireEyeJSON(target):
    # the plan: build a new dictionary from the existing dictionary.
    # for any given dictionary entry,
    # if it's value is another dictionary,
    #    then make it a list with that dictionary as the only value,
    #     then recurse through each value to make sure that this problem
    #        isn't recurring lower down
    # if its value is a list, then make a list in the new value,
    #     then walk each value in the list & recurse through the original
    #       list to make sure the values work
    # if it's just a base value (string, integer, float),
    #    then copy the value into the new dictionary.
    #
    # None of this would be necessary if fireeye would just be
    # consistent about their JSON
    #
    #
    if isinstance(target, list):
        response = []
        for entry in target:
            response.append(fixFireEyeJSON(entry))
    elif isinstance(target, dict):
        response = {}
        for key in target:
            if isinstance(target[key], str):
                if not target[key]:
                    continue
                response[key] = target[key]
            elif isinstance(target[key], unicode):
                if not target[key]:
                    continue
                response[key] = target[key]
            elif isinstance(target[key], int):
                response[key] = target[key]
            elif isinstance(target[key], float):
                response[key] = target[key]
            elif isinstance(target[key], list):
                if not target[key]:
                    continue
                response[key] = []
                for entry in target[key]:
                    response[key].append(fixFireEyeJSON(entry))
            elif isinstance(target[key], dict):
                if not target[key]:
                    continue
                response[key] = []
                response[key].append(fixFireEyeJSON(target[key]))
    else:
        response = target
    return response
