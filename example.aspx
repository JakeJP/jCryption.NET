<%@  Language="C#" Inherits="jCryption.SecurePage" %>
<html>
<head>
    <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
    <script type="text/javascript" src="Scripts/jquery.jcryption.3.0.1.js"></script>
    <script type="text/javascript">
        $(function () {
            $("#normal").jCryption({
                getKeysURL: "<%= Request.Path %>?getPublicKey=true",
		            handshakeURL: "<%= Request.Path %>?handshake=true"
		        });
		    });
    </script>
</head>

<body>
    <h1>ASPX example</h1>
    <form id="normal" class="general" method="post">
        <fieldset>
            <table border="0" cellspacing="5" cellpadding="0">
                <tbody>
                    <tr>
                        <td>Sex:</td>
                        <td>
                            <input class="radio" name="Sex" type="radio" value="male" checked="checked" />Male

								<input class="radio" name="Sex" type="radio" value="female" />Female</td>
                    </tr>
                    <tr>
                        <td>Firstname:</td>
                        <td>
                            <input class="text" name="Firstname" type="text" value="John" /></td>
                    </tr>
                    <tr>
                        <td>Lastname:</td>
                        <td>
                            <input class="text" name="Lastname" type="text" value="Wayne" /></td>
                    </tr>
                    <tr>
                        <td>E-Mail:</td>
                        <td>
                            <input class="text" name="Email" type="text" value="john@wayne.com" /></td>
                    </tr>
                    <tr>
                        <td>What would you like to eat?</td>
                        <td>
                            <input class="checkbox" name="Food[]" type="checkbox" value="pizza" checked="checked" />Pizza

								<input class="checkbox" name="Food[]" type="checkbox" value="hamburger" />Hamburger

								<input class="checkbox" name="Food[]" type="checkbox" value="salad" checked="checked" />Salad

								<input class="checkbox" name="Food[]" type="checkbox" value="steak" />Steak</td>
                    </tr>
                    <tr>
                        <td>Age:</td>
                        <td>
                            <select name="age">
                                <option value="under 18" selected="selected">under 18</option>
                                <option value="over 18">over 18</option>
                                <option value="over 30">over 30</option>
                            </select></td>
                    </tr>
                    <tr valign="top">
                        <td valign="top">I like (you can select more than one):</td>
                        <td>
                            <select name="likes[]" size="5" multiple="multiple">
                                <option value="Michael Jackson">Michael Jackson</option>
                                <option value="rainy wheater" selected="selected">rainy wheater</option>
                                <option value="a hot summer">a hot summer</option>
                                <option value="small cats" selected="selected">small cats</option>
                                <option value="funny movies">funny movies</option>
                                <option value="I like everything" selected="selected">I like everything</option>
                            </select></td>
                    </tr>
                    <tr>
                        <td></td>
                        <td>
                            <input title="Submit" alt="Submit" name="submitButton" type="submit" value="Submit" class="submit" />
                            <input title="Reset" alt="Reset" name="reset" type="reset" value="Reset" /></td>
                    </tr>
                </tbody>
            </table>
        </fieldset>
    </form>

    <div>
        <ul>
        <% foreach (var _k in Request.Form.AllKeys){ %> 
            <li><b><%=_k%></b> = <span><%=Request.Form[_k]%></span></li>
        <% } %>
        </ul>
    </div>
</body>
</html>
