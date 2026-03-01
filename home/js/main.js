$('#getting-started').countdown('2023/01/01', function(event) { 
	$("#day").html(event.strftime('%D <em>days</em>')); 
	$("#hour").html(event.strftime('%H <em>hours</em>'));
	$("#min").html(event.strftime('%M <em>minutes</em>'));
	$("#sec").html(event.strftime('%S <em>seconds</em>'));
	});
