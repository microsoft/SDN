$paVNICCompartment = get-netcompartment |? { $_.CompartmentGuid -eq "{9fa803c5-68bc-48bb-a573-9d4ca9c5790a}" }
ping -c $paVNICCompartment.CompartmentId  $args