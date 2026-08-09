/*
 * Ready-to-apply replacement for
 *   src/main/resources/lessons/xss/js/stored-xss.js
 *
 * Derived from h0g3ria PR #49 (fix/xss-stored-follow-up), which is the only branch in the
 * 168-PR corpus that touches this file. The comment list is now built with jQuery element
 * constructors and .text(), so nothing coming back from the server is ever parsed as HTML.
 * This closes the DOM sink that the previous html.replace('COMMENT', ...) + append() pattern
 * left open, independently of whatever encoding the server applies.
 */
$(document).ready(function () {
    $("#postComment").on("click", function () {
        var commentInput = $("#commentInput").val();
        $.ajax({
            type: 'POST',
            url: 'CrossSiteScriptingStored/stored-xss',
            data: JSON.stringify({text: commentInput}),
            contentType: "application/json",
            dataType: 'json'
        }).then(
            function () {
                getChallenges();
                $("#commentInput").val('');
            }
        )
    })

    getChallenges();

    function getChallenges() {
        $("#list").empty();
        $.get('CrossSiteScriptingStored/stored-xss', function (result, status) {
            for (var i = 0; i < result.length; i++) {
                var comment = $('<li>').addClass('comment');
                var image = $('<div>').addClass('pull-left').append(
                    $('<img>').addClass('avatar').attr({src: 'images/avatar1.png', alt: 'avatar'})
                );
                var heading = $('<div>').addClass('comment-heading').append(
                    $('<h4>').addClass('user').text(result[i].user),
                    $('<h5>').addClass('time').text(result[i].dateTime)
                );
                var body = $('<div>').addClass('comment-body').append(
                    heading,
                    $('<p>').text(result[i].text)
                );
                comment.append(image, body);
                $("#list").append(comment);
            }

        });
    }
})
